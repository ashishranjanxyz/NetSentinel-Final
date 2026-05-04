// Minimal text-PDF generator. Builds a PDF by hand to avoid pulling in a
// dependency. Layout is single-column text; sufficient for a downloadable
// scan report from the serverless API.

function escapePdfText(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrap(text, max = 95) {
  const out = [];
  for (const raw of String(text).split('\n')) {
    let line = raw;
    while (line.length > max) {
      let cut = line.lastIndexOf(' ', max);
      if (cut < 40) cut = max;
      out.push(line.slice(0, cut));
      line = line.slice(cut).trimStart();
    }
    out.push(line);
  }
  return out;
}

function buildPdf(lines) {
  const pageHeight = 792;
  const pageWidth = 612;
  const marginX = 50;
  const top = pageHeight - 60;
  const lineHeight = 14;
  const linesPerPage = Math.floor((top - 60) / lineHeight);
  const pages = [];
  for (let i = 0; i < lines.length; i += linesPerPage) {
    pages.push(lines.slice(i, i + linesPerPage));
  }
  if (!pages.length) pages.push(['(empty report)']);

  const objects = [];
  const pageIds = pages.map((_, i) => 4 + i * 2);
  const contentIds = pages.map((_, i) => 5 + i * 2);

  // 1: Catalog
  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  // 2: Pages
  objects.push(
    `<< /Type /Pages /Count ${pages.length} /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] >>`
  );
  // 3: Font
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>');
  // 4..: Page + Contents pairs
  pages.forEach((pageLines, idx) => {
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentIds[idx]} 0 R >>`
    );
    let stream = `BT /F1 10 Tf ${marginX} ${top} Td ${lineHeight} TL\n`;
    pageLines.forEach((ln, i) => {
      const t = `(${escapePdfText(ln)}) Tj`;
      stream += i === 0 ? `${t}\n` : `T*\n${t}\n`;
    });
    stream += 'ET';
    objects.push(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`);
  });

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((body, i) => {
    offsets.push(Buffer.byteLength(pdf, 'latin1'));
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefStart = Buffer.byteLength(pdf, 'latin1');
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i <= objects.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(pdf, 'latin1');
}

function reportLines(target, scanType, result) {
  const lines = [];
  lines.push('NetSentinel Scan Report');
  lines.push('=======================');
  lines.push(`Target:    ${target}`);
  lines.push(`Scan type: ${scanType}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');

  const ai = result?.port_scan?.ai || {};
  const ports = result?.port_scan?.ports || [];
  lines.push(`Overall risk:  ${ai.risk_level || 'UNKNOWN'}`);
  lines.push(`AI confidence: ${ai.confidence ?? 0}%`);
  lines.push(`Open ports:    ${ports.length}`);
  lines.push('');

  if (ports.length) {
    lines.push('Open Ports');
    lines.push('----------');
    for (const p of ports) {
      lines.push(`  ${String(p.port).padEnd(6)} ${(p.service || '').padEnd(14)} ${p.known_risk || ''}`);
    }
    lines.push('');
  }

  const cve = result?.cve || [];
  if (cve.length) {
    lines.push('CVE Findings');
    lines.push('------------');
    for (const c of cve) {
      lines.push(`  ${c.id}  CVSS ${c.cvss}  ${c.severity}`);
      wrap(`    ${c.desc}`, 90).forEach((l) => lines.push(l));
      wrap(`    Fix: ${c.fix}`, 90).forEach((l) => lines.push(l));
    }
    lines.push('');
  }

  const ssl = result?.ssl || {};
  lines.push('SSL Certificate');
  lines.push('---------------');
  lines.push(`  Valid:    ${ssl.valid ? 'yes' : 'no'}`);
  lines.push(`  Issuer:   ${ssl.issuer || 'N/A'}`);
  lines.push(`  Protocol: ${ssl.protocol || 'N/A'}`);
  lines.push(`  Expires:  ${ssl.expires || 'N/A'}`);
  lines.push('');

  const geo = result?.ip_geo || {};
  lines.push('IP Geolocation');
  lines.push('--------------');
  lines.push(`  IP:      ${geo.ip || 'N/A'}`);
  lines.push(`  Country: ${geo.country || 'N/A'}`);
  lines.push(`  ISP:     ${geo.isp || 'N/A'}`);
  lines.push(`  Org:     ${geo.org || 'N/A'}`);
  lines.push('');

  const hh = result?.http_headers || {};
  if (Array.isArray(hh.headers)) {
    lines.push('HTTP Security Headers');
    lines.push('---------------------');
    lines.push(`  Score: ${hh.score || 'N/A'}`);
    for (const h of hh.headers) {
      lines.push(`  [${h.present ? 'x' : ' '}] ${h.name}`);
    }
    lines.push('');
  }

  return lines;
}

export default async (req) => {
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'POST required' }), {
      status: 405,
      headers: { 'content-type': 'application/json' },
    });
  }
  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }
  const target = body.target || 'unknown';
  const scanType = body.scan_type || 'basic';
  const result = body.result || {};
  const lines = reportLines(target, scanType, result);
  const pdf = buildPdf(lines);
  const safeTarget = String(target).replace(/[^a-z0-9._-]/gi, '_');
  return new Response(pdf, {
    status: 200,
    headers: {
      'content-type': 'application/pdf',
      'content-disposition': `attachment; filename="netsentinel_${safeTarget}.pdf"`,
    },
  });
};

export const config = { path: '/api/pdf' };
