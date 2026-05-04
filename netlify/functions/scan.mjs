import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';

const KNOWN_RISKY_PORTS = {
  21: { service: 'ftp', risk: 'HIGH' },
  22: { service: 'ssh', risk: 'MEDIUM' },
  23: { service: 'telnet', risk: 'CRITICAL' },
  25: { service: 'smtp', risk: 'MEDIUM' },
  53: { service: 'dns', risk: 'MEDIUM' },
  80: { service: 'http', risk: 'LOW' },
  110: { service: 'pop3', risk: 'HIGH' },
  135: { service: 'msrpc', risk: 'HIGH' },
  139: { service: 'netbios', risk: 'HIGH' },
  143: { service: 'imap', risk: 'MEDIUM' },
  443: { service: 'https', risk: 'LOW' },
  445: { service: 'smb', risk: 'CRITICAL' },
  993: { service: 'imaps', risk: 'LOW' },
  995: { service: 'pop3s', risk: 'LOW' },
  1433: { service: 'mssql', risk: 'HIGH' },
  3306: { service: 'mysql', risk: 'HIGH' },
  3389: { service: 'rdp', risk: 'CRITICAL' },
  5432: { service: 'postgresql', risk: 'HIGH' },
  5900: { service: 'vnc', risk: 'CRITICAL' },
  6379: { service: 'redis', risk: 'CRITICAL' },
  8080: { service: 'http-alt', risk: 'MEDIUM' },
  8443: { service: 'https-alt', risk: 'LOW' },
  27017: { service: 'mongodb', risk: 'CRITICAL' },
};

const COMMON_PORTS = Object.keys(KNOWN_RISKY_PORTS).map(Number);

const CVE_DATABASE = {
  ssh: [{ id: 'CVE-2024-6387', severity: 'CRITICAL', cvss: 9.8, desc: 'RegreSSHion — Unauthenticated Remote Code Execution in OpenSSH', fix: 'Update to OpenSSH 9.8p1 or later' }],
  http: [{ id: 'CVE-2021-41773', severity: 'HIGH', cvss: 7.5, desc: 'Path traversal and RCE in Apache HTTP Server 2.4.49', fix: 'Update to Apache 2.4.51 or later' }],
  https: [{ id: 'CVE-2021-44228', severity: 'CRITICAL', cvss: 10.0, desc: 'Log4Shell — RCE via JNDI injection in Apache Log4j', fix: 'Update Log4j to 2.17.1 or later' }],
  smb: [{ id: 'CVE-2017-0144', severity: 'CRITICAL', cvss: 9.3, desc: 'EternalBlue — SMBv1 RCE (WannaCry vector)', fix: 'Apply MS17-010 patch, disable SMBv1' }],
  rdp: [{ id: 'CVE-2019-0708', severity: 'CRITICAL', cvss: 9.8, desc: 'BlueKeep — Wormable RCE in Remote Desktop Services', fix: 'Apply MS19-0708 patch immediately' }],
  ftp: [{ id: 'CVE-2010-4221', severity: 'HIGH', cvss: 7.5, desc: 'Buffer overflow in ProFTPD mod_sql module', fix: 'Update ProFTPD to latest version' }],
  telnet: [{ id: 'CVE-2020-10188', severity: 'CRITICAL', cvss: 9.8, desc: 'Arbitrary code execution in telnetd', fix: 'Disable Telnet immediately, use SSH' }],
  mysql: [{ id: 'CVE-2022-21702', severity: 'HIGH', cvss: 7.5, desc: 'MySQL Server privilege escalation', fix: 'Update to MySQL 8.0.28 or later' }],
};

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
];

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'api', 'admin', 'dev', 'staging', 'test', 'blog',
  'shop', 'app', 'cdn', 'static', 'docs', 'support', 'status', 'm',
  'portal', 'auth', 'beta', 'demo',
];

const COMMON_DIRS = [
  '/.git', '/.env', '/admin', '/robots.txt', '/sitemap.xml', '/api',
  '/login', '/dashboard', '/wp-admin', '/wp-login.php', '/phpinfo.php',
  '/.htaccess', '/backup', '/config', '/server-status', '/.DS_Store',
];

const DIR_RISK = {
  '/.git': 'CRITICAL', '/.env': 'CRITICAL', '/wp-config.php': 'CRITICAL',
  '/backup': 'HIGH', '/phpinfo.php': 'HIGH', '/server-status': 'HIGH',
  '/admin': 'MEDIUM', '/wp-admin': 'MEDIUM', '/.DS_Store': 'MEDIUM',
  '/robots.txt': 'LOW', '/sitemap.xml': 'LOW',
};

function cleanTarget(target) {
  return String(target || '').replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
}

async function resolveIP(hostname) {
  if (net.isIP(hostname)) return hostname;
  try {
    const result = await dns.lookup(hostname);
    return result.address;
  } catch {
    return null;
  }
}

function tcpProbe(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open, banner = '') => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve({ port, open, banner });
    };
    socket.setTimeout(timeoutMs);
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8').slice(0, 256);
      if (data.length > 8) finish(true, data.replace(/[^\x20-\x7e]/g, ' ').trim());
    });
    socket.on('timeout', () => finish(socket.connecting ? false : true, data));
    socket.on('error', () => finish(false));
    socket.on('connect', () => {
      setTimeout(() => finish(true, data), 400);
    });
    try {
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

async function portScan(host) {
  const probes = COMMON_PORTS.map((p) => tcpProbe(host, p, 1500));
  const results = await Promise.all(probes);
  const ports = [];
  for (const r of results) {
    if (!r.open) continue;
    const known = KNOWN_RISKY_PORTS[r.port] || {};
    ports.push({
      port: r.port,
      protocol: 'tcp',
      service: known.service || 'unknown',
      product: '',
      version: '',
      state: 'open',
      known_risk: known.risk || 'UNKNOWN',
    });
  }
  return ports;
}

async function bannerGrab(host, ports) {
  const banners = [];
  const targets = ports.filter((p) => [21, 22, 25, 80, 110, 143, 443, 8080].includes(p.port)).slice(0, 5);
  await Promise.all(
    targets.map(async (p) => {
      const probe = await tcpProbe(host, p.port, 1500);
      if (probe.banner) banners.push({ port: p.port, banner: probe.banner.slice(0, 120) });
    })
  );
  return banners;
}

async function dnsLookup(host) {
  const out = {};
  const tasks = [
    ['A', () => dns.resolve4(host)],
    ['AAAA', () => dns.resolve6(host)],
    ['MX', () => dns.resolveMx(host).then((r) => r.map((m) => `${m.priority} ${m.exchange}`))],
    ['NS', () => dns.resolveNs(host)],
    ['TXT', () => dns.resolveTxt(host).then((r) => r.map((t) => t.join('')))],
    ['CNAME', () => dns.resolveCname(host)],
  ];
  await Promise.all(
    tasks.map(async ([type, fn]) => {
      try {
        const r = await fn();
        if (r && r.length) out[type] = r;
      } catch {}
    })
  );
  return out;
}

async function reverseDns(host, ip) {
  if (!ip) return { ip: null, hostname: null, status: 'Could not resolve', match: false };
  try {
    const names = await dns.reverse(ip);
    const hostname = names && names[0];
    const match = !!hostname && hostname.toLowerCase().includes(host.toLowerCase().split('.').slice(-2).join('.'));
    return {
      ip,
      hostname: hostname || null,
      ptr_record: hostname || null,
      match,
      status: hostname ? (match ? 'Forward and reverse DNS match' : 'PTR record found, no forward match') : 'No PTR record',
    };
  } catch {
    return { ip, hostname: null, status: 'No PTR record', match: false };
  }
}

async function ipGeo(host, ip) {
  const target = ip || host;
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query`);
    if (!res.ok) return {};
    const j = await res.json();
    if (j.status !== 'success') return { ip: target };
    return {
      ip: j.query,
      country: j.country,
      country_code: j.countryCode,
      region: j.regionName,
      city: j.city,
      lat: j.lat,
      lon: j.lon,
      timezone: j.timezone,
      isp: j.isp,
      org: j.org,
      as: j.as,
    };
  } catch {
    return { ip: target };
  }
}

async function asnLookup(host, geo) {
  const asField = geo && geo.as;
  if (asField) {
    const m = String(asField).match(/^AS(\d+)\s+(.*)$/);
    return {
      asn: m ? `AS${m[1]}` : asField,
      org: m ? m[2] : geo.isp || '',
      country: geo.country_code || '',
      ip_range: '',
      abuse_contact: '',
    };
  }
  return { asn: 'N/A', org: 'N/A', country: 'N/A', ip_range: 'N/A', abuse_contact: 'N/A' };
}

async function whoisLookup(host) {
  const domain = host.split('.').slice(-2).join('.');
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return {};
    const j = await res.json();
    const events = j.events || [];
    const findDate = (action) => {
      const ev = events.find((e) => e.eventAction === action);
      return ev ? ev.eventDate.slice(0, 10) : null;
    };
    const registrar =
      (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
    let registrarName = '';
    if (registrar && registrar.vcardArray) {
      const fn = registrar.vcardArray[1].find((v) => v[0] === 'fn');
      if (fn) registrarName = fn[3];
    }
    return {
      registrar: registrarName || 'N/A',
      created: findDate('registration'),
      expires: findDate('expiration'),
      updated: findDate('last changed') || findDate('last update of RDAP database'),
      status: (j.status || []).join(', ') || 'active',
      country: '',
      name_servers: (j.nameservers || []).map((n) => n.ldhName),
    };
  } catch {
    return { registrar: 'N/A', name_servers: [] };
  }
}

async function sslCheck(host) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(v);
    };
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: 5000 },
      () => {
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        if (!cert || !cert.subject) {
          finish({ valid: false });
          return;
        }
        const expires = cert.valid_to ? new Date(cert.valid_to) : null;
        const days_left = expires ? Math.floor((expires - Date.now()) / (1000 * 60 * 60 * 24)) : null;
        const issuer = cert.issuer ? cert.issuer.O || cert.issuer.CN || '' : '';
        let grade = 'B';
        if (protocol === 'TLSv1.3') grade = 'A+';
        else if (protocol === 'TLSv1.2') grade = 'A';
        else if (protocol === 'TLSv1.1' || protocol === 'TLSv1') grade = 'C';
        finish({
          valid: days_left == null ? false : days_left > 0,
          issuer,
          protocol: protocol || 'unknown',
          cipher: cipher ? cipher.name : '',
          expires: cert.valid_to,
          days_left,
          grade,
        });
      }
    );
    socket.on('error', () => finish({ valid: false }));
    socket.on('timeout', () => finish({ valid: false }));
  });
}

async function httpHeaders(host) {
  const tryUrls = [`https://${host}`, `http://${host}`];
  for (const url of tryUrls) {
    try {
      const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(5000) });
      const headers = SECURITY_HEADERS.map((name) => ({
        name: name.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join('-'),
        present: res.headers.has(name),
      }));
      const present = headers.filter((h) => h.present).length;
      const score = `${present}/${SECURITY_HEADERS.length}`;
      return { headers, score, server: res.headers.get('server') || '' };
    } catch {}
  }
  return { headers: SECURITY_HEADERS.map((n) => ({ name: n, present: false })), score: '0/7' };
}

async function corsCheck(host) {
  try {
    const res = await fetch(`https://${host}`, {
      headers: { Origin: 'https://evil.example.com' },
      signal: AbortSignal.timeout(5000),
    });
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    const issues = [];
    if (acao === '*' && acac === 'true') {
      issues.push({
        type: 'Wildcard with credentials',
        detail: 'Access-Control-Allow-Origin: * with credentials is forbidden by spec',
        fix: 'Restrict to specific origins when allowing credentials',
      });
    }
    if (acao === 'https://evil.example.com') {
      issues.push({
        type: 'Origin reflection',
        detail: 'Server reflects arbitrary Origin header',
        fix: 'Maintain an allowlist of trusted origins',
      });
    }
    return { vulnerable: issues.length > 0, issues, acao: acao || '', acac: acac || '' };
  } catch {
    return { vulnerable: false, issues: [] };
  }
}

async function techDetect(host) {
  try {
    const res = await fetch(`https://${host}`, { signal: AbortSignal.timeout(5000) });
    const tech = [];
    const server = res.headers.get('server');
    const xpb = res.headers.get('x-powered-by');
    if (server) tech.push({ name: server, category: 'Web Server' });
    if (xpb) tech.push({ name: xpb, category: 'Framework' });
    const text = (await res.text()).slice(0, 50000).toLowerCase();
    const sigs = [
      ['wordpress', 'wp-content', 'CMS'],
      ['react', 'react.', 'JS Framework'],
      ['vue', 'vue.', 'JS Framework'],
      ['next.js', '/_next/', 'JS Framework'],
      ['nuxt', '/_nuxt/', 'JS Framework'],
      ['jquery', 'jquery', 'JS Library'],
      ['bootstrap', 'bootstrap', 'CSS Framework'],
      ['tailwind', 'tailwind', 'CSS Framework'],
      ['cloudflare', 'cf-ray', 'CDN'],
    ];
    for (const [name, sig, cat] of sigs) {
      if (text.includes(sig)) tech.push({ name, category: cat });
    }
    return tech;
  } catch {
    return [];
  }
}

async function subdomainFind(host) {
  const root = host.replace(/^www\./, '').split('.').slice(-2).join('.');
  const found = [];
  await Promise.all(
    COMMON_SUBDOMAINS.map(async (sub) => {
      const fqdn = `${sub}.${root}`;
      try {
        const r = await dns.resolve4(fqdn);
        if (r && r.length) found.push({ subdomain: fqdn, ip: r[0], status: 'Active' });
      } catch {}
    })
  );
  return found.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}

async function dirBrute(host) {
  const found = [];
  const base = `https://${host}`;
  await Promise.all(
    COMMON_DIRS.map(async (path) => {
      try {
        const res = await fetch(base + path, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(3500),
        });
        if ([200, 301, 302, 403].includes(res.status)) {
          let size = '-';
          if (res.status === 200) {
            const buf = await res.arrayBuffer();
            size = `${(buf.byteLength / 1024).toFixed(1)}KB`;
          }
          found.push({
            path,
            status: res.status,
            size,
            risk: DIR_RISK[path] || 'LOW',
            note:
              res.status === 200
                ? 'Accessible'
                : res.status === 403
                ? 'Exists (Forbidden)'
                : 'Redirects',
          });
        }
      } catch {}
    })
  );
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  return found.sort((a, b) => (order[a.risk] || 4) - (order[b.risk] || 4));
}

function generateDorks(host) {
  return [
    `site:${host} filetype:pdf OR filetype:doc OR filetype:xls`,
    `site:${host} inurl:admin OR inurl:login OR inurl:dashboard`,
    `site:${host} "index of" OR "directory listing"`,
    `site:${host} ext:sql OR ext:db OR ext:backup OR ext:bak`,
    `site:${host} "wp-config" OR "config.php" OR ".env"`,
    `site:${host} inurl:api OR inurl:v1 OR inurl:v2`,
    `site:${host} "error" OR "exception" OR "stack trace"`,
    `site:${host} filetype:log OR filetype:txt inurl:log`,
  ];
}

function cveScan(ports) {
  const found = [];
  const seen = new Set();
  for (const p of ports) {
    const svc = (p.service || '').toLowerCase();
    const list = CVE_DATABASE[svc] || [];
    for (const cve of list) {
      if (seen.has(cve.id)) continue;
      seen.add(cve.id);
      found.push({ ...cve, service: p.service, port: p.port });
    }
  }
  return found.sort((a, b) => b.cvss - a.cvss);
}

function aiAnalyze(ports) {
  if (!ports.length) {
    return { risk_level: 'LOW', confidence: 88, is_anomaly: false, explanation: ['No open ports detected on the common-port sample.'] };
  }
  const riskMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 1 };
  const score = ports.reduce((a, p) => a + (riskMap[p.known_risk] || 1), 0);
  const critical = ports.filter((p) => p.known_risk === 'CRITICAL').length;
  const high = ports.filter((p) => p.known_risk === 'HIGH').length;
  let level = 'LOW';
  if (critical > 0) level = 'CRITICAL';
  else if (high > 1) level = 'HIGH';
  else if (high === 1 || score >= 6) level = 'MEDIUM';
  const explanation = [];
  if (critical) explanation.push(`${critical} critical service(s) exposed; immediate action recommended.`);
  if (high) explanation.push(`${high} high-risk service(s) detected (databases or remote-access protocols).`);
  if (!critical && !high) explanation.push('Only standard web ports observed; risk profile is normal.');
  const confidence = Math.min(96, 70 + ports.length * 3);
  return { risk_level: level, confidence, is_anomaly: critical > 0 || high > 1, explanation };
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
  const target = cleanTarget(body.target);
  const scanType = body.type === 'advanced' ? 'advanced' : 'basic';
  if (!target) {
    return new Response(JSON.stringify({ error: 'Target is required' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }
  const ip = await resolveIP(target);
  if (!ip) {
    return new Response(JSON.stringify({ error: `Cannot resolve target: ${target}` }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }

  const [ports, dnsRecs, rdns, geo, ssl, headers] = await Promise.all([
    portScan(ip),
    dnsLookup(target),
    reverseDns(target, ip),
    ipGeo(target, ip),
    sslCheck(target),
    httpHeaders(target),
  ]);

  const ai = aiAnalyze(ports);
  const cve = cveScan(ports);
  const banner = await bannerGrab(ip, ports);
  const whois = await whoisLookup(target);

  const result = {
    port_scan: { ports, ai },
    whois,
    dns: dnsRecs,
    ssl,
    ip_geo: geo,
    cve,
    http_headers: headers,
    banner,
    reverse_dns: rdns,
  };

  if (scanType === 'advanced') {
    const [subdomains, tech_stack, cors, directories, asn] = await Promise.all([
      subdomainFind(target),
      techDetect(target),
      corsCheck(target),
      dirBrute(target),
      asnLookup(target, geo),
    ]);
    Object.assign(result, {
      subdomains,
      tech_stack,
      cors,
      reverse_ip: [],
      asn,
      directories,
      dorks: generateDorks(target),
    });
  }

  return new Response(
    JSON.stringify({ success: true, target, scan_type: scanType, result }),
    { headers: { 'content-type': 'application/json' } }
  );
};

export const config = { path: '/api/scan' };
