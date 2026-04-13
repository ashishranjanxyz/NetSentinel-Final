from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
import datetime, os, tempfile

BLUE = colors.HexColor("#2563eb")
DARK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
GREEN = colors.HexColor("#16a34a")
RED = colors.HexColor("#dc2626")
ORANGE = colors.HexColor("#ea580c")
YELLOW = colors.HexColor("#ca8a04")
LIGHT = colors.HexColor("#f9fafb")
BORDER = colors.HexColor("#e5e7eb")

RISK_COLORS = {
    "CRITICAL": colors.HexColor("#fef2f2"),
    "HIGH": colors.HexColor("#fff7ed"),
    "MEDIUM": colors.HexColor("#fefce8"),
    "LOW": colors.HexColor("#f0fdf4"),
}
RISK_TEXT_COLORS = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
}

def generate_pdf(target, scan_result, scan_type):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", prefix="netsentinel_")
    tmp.close()
    path = tmp.name

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    story = []

    def h(text, size=16, color=DARK, bold=True, space_after=6):
        return Paragraph(f'<font color="{color.hexval()}" size="{size}"><b>{text}</b></font>' if bold else f'<font color="{color.hexval()}" size="{size}">{text}</font>',
                         ParagraphStyle("h", fontName="Helvetica-Bold" if bold else "Helvetica", fontSize=size, textColor=color, spaceAfter=space_after))

    def p(text, size=10, color=MUTED, space_after=4):
        return Paragraph(text, ParagraphStyle("p", fontName="Helvetica", fontSize=size, textColor=color, spaceAfter=space_after, leading=16))

    def section_title(text):
        return [
            Spacer(1, 0.4*cm),
            Paragraph(f'<font color="#2563eb" size="11"><b>{text.upper()}</b></font>',
                      ParagraphStyle("st", fontName="Helvetica-Bold", fontSize=11, textColor=BLUE, spaceAfter=6)),
            HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8),
        ]

    def risk_badge(risk):
        c = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(risk, "#6b7280")
        return f'<font color="{c}"><b>{risk}</b></font>'

    # ── HEADER ──────────────────────────────────
    header_data = [[
        Paragraph('<font color="#ffffff" size="20"><b>Net</b></font><font color="#93c5fd" size="20"><b>Sentinel</b></font>',
                  ParagraphStyle("logo", fontName="Helvetica-Bold", fontSize=20)),
        Paragraph(f'<font color="#9ca3af" size="9">Vulnerability Assessment Report<br/>'
                  f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>'
                  f'Scan Type: {"Advanced (20 Modules)" if scan_type == "advanced" else "Basic (10 Modules)"}</font>',
                  ParagraphStyle("hdr", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#9ca3af"), alignment=TA_RIGHT))
    ]]
    header_table = Table(header_data, colWidths=["50%", "50%"])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING", (0, 0), (0, -1), 16),
        ("RIGHTPADDING", (-1, 0), (-1, -1), 16),
    ]))
    story.append(header_table)

    # Blue accent bar
    story.append(HRFlowable(width="100%", thickness=3, color=BLUE, spaceAfter=12))

    # ── TARGET INFO ──────────────────────────────
    ai = scan_result.get("port_scan", {}).get("ai", {})
    ports = scan_result.get("port_scan", {}).get("ports", [])
    cves = scan_result.get("cve", [])
    risk = ai.get("risk_level", "UNKNOWN")

    summary_data = [
        [Paragraph(f'<font color="#6b7280" size="9">TARGET</font>', ParagraphStyle("lbl", fontSize=9, textColor=MUTED)),
         Paragraph(f'<font color="#6b7280" size="9">OVERALL RISK</font>', ParagraphStyle("lbl", fontSize=9, textColor=MUTED, alignment=TA_CENTER)),
         Paragraph(f'<font color="#6b7280" size="9">OPEN PORTS</font>', ParagraphStyle("lbl", fontSize=9, textColor=MUTED, alignment=TA_CENTER)),
         Paragraph(f'<font color="#6b7280" size="9">CVEs FOUND</font>', ParagraphStyle("lbl", fontSize=9, textColor=MUTED, alignment=TA_CENTER)),
         Paragraph(f'<font color="#6b7280" size="9">AI CONFIDENCE</font>', ParagraphStyle("lbl", fontSize=9, textColor=MUTED, alignment=TA_CENTER))],
        [Paragraph(f'<font color="#111827" size="14"><b>{target}</b></font>', ParagraphStyle("tv", fontSize=14, fontName="Helvetica-Bold")),
         Paragraph(f'<font color="{RISK_TEXT_COLORS.get(risk, MUTED).hexval()}" size="18"><b>{risk}</b></font>', ParagraphStyle("rv", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(f'<font color="#2563eb" size="18"><b>{len(ports)}</b></font>', ParagraphStyle("pv", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(f'<font color="#ea580c" size="18"><b>{len(cves)}</b></font>', ParagraphStyle("cv2", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(f'<font color="#16a34a" size="18"><b>{ai.get("confidence", 0)}%</b></font>', ParagraphStyle("av", fontSize=18, fontName="Helvetica-Bold", alignment=TA_CENTER))]
    ]
    summary_table = Table(summary_data, colWidths=["30%", "17.5%", "17.5%", "17.5%", "17.5%"])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LINEAFTER", (0, 0), (-2, -1), 0.5, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.extend(section_title("Executive Summary"))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*cm))

    # AI explanation
    for line in ai.get("explanation", []):
        story.append(p(f"• {line}", size=9, color=MUTED))

    # ── PORT SCAN ────────────────────────────────
    if ports:
        story.extend(section_title("Port Scanner + AI Analysis"))
        port_header = ["Port", "Protocol", "Service", "Version", "Risk", "Recommendation"]
        port_rows = [port_header]
        for pt in ports:
            r_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(pt.get("known_risk", ""), "#6b7280")
            rec = {"CRITICAL": "Close immediately", "HIGH": "Restrict access", "MEDIUM": "Monitor closely", "LOW": "Keep updated"}.get(pt.get("known_risk", ""), "Review")
            port_rows.append([
                Paragraph(f'<font color="#2563eb"><b>{pt["port"]}/tcp</b></font>', ParagraphStyle("p", fontSize=9, fontName="Helvetica-Bold")),
                Paragraph(pt.get("protocol", "tcp"), ParagraphStyle("p", fontSize=9)),
                Paragraph(pt.get("service", ""), ParagraphStyle("p", fontSize=9)),
                Paragraph(f'{pt.get("product", "")} {pt.get("version", "")}'.strip()[:30], ParagraphStyle("p", fontSize=8, textColor=MUTED)),
                Paragraph(f'<font color="{r_color}"><b>{pt.get("known_risk", "UNKNOWN")}</b></font>', ParagraphStyle("p", fontSize=9, fontName="Helvetica-Bold")),
                Paragraph(rec, ParagraphStyle("p", fontSize=8, textColor=MUTED)),
            ])
        t = Table(port_rows, colWidths=["13%", "10%", "12%", "22%", "13%", "30%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ]))
        story.append(t)

    # ── WHOIS ────────────────────────────────────
    whois = scan_result.get("whois", {})
    if whois and not whois.get("error"):
        story.extend(section_title("WHOIS Information"))
        whois_data = [
            ["Registrar", whois.get("registrar", "N/A"), "Country", whois.get("country", "N/A")],
            ["Created", whois.get("created", "N/A"), "Expires", whois.get("expires", "N/A")],
            ["Last Updated", whois.get("updated", "N/A"), "Status", whois.get("status", "N/A")],
            ["Name Servers", ", ".join(whois.get("name_servers", [])[:2]), "Organization", whois.get("org", "N/A")],
        ]
        t = Table([[Paragraph(f'<font color="#6b7280" size="9">{r[0]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[1]}</b></font>', ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold")),
                    Paragraph(f'<font color="#6b7280" size="9">{r[2]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[3]}</b></font>', ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold"))]
                   for r in whois_data], colWidths=["18%", "32%", "18%", "32%"])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # ── DNS ──────────────────────────────────────
    dns_data = scan_result.get("dns", {})
    if dns_data and not dns_data.get("error"):
        story.extend(section_title("DNS Records"))
        dns_rows = [["Record Type", "Value"]]
        for rtype, vals in dns_data.items():
            if isinstance(vals, list):
                for v in vals[:3]:
                    dns_rows.append([rtype, str(v)])
            else:
                dns_rows.append([rtype, str(vals)])
        t = Table([[Paragraph(f'<font color="#2563eb" size="9"><b>{r[0]}</b></font>', ParagraphStyle("p", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9">{r[1]}</font>', ParagraphStyle("p", fontSize=9))]
                   for r in dns_rows], colWidths=["15%", "85%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # ── SSL ──────────────────────────────────────
    ssl = scan_result.get("ssl", {})
    if ssl:
        story.extend(section_title("SSL Certificate"))
        ssl_rows = [
            ["Status", "Valid" if ssl.get("valid") else "Invalid", "Grade", ssl.get("grade", "N/A")],
            ["Issuer", ssl.get("issuer", "N/A"), "Protocol", ssl.get("protocol", "N/A")],
            ["Expires", ssl.get("expires", "N/A"), "Days Remaining", str(ssl.get("days_left", "N/A"))],
        ]
        t = Table([[Paragraph(f'<font color="#6b7280" size="9">{r[0]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[1]}</b></font>', ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold")),
                    Paragraph(f'<font color="#6b7280" size="9">{r[2]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[3]}</b></font>', ParagraphStyle("v", fontSize=9, fontName="Helvetica-Bold"))]
                   for r in ssl_rows], colWidths=["18%", "32%", "18%", "32%"])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # ── CVE ──────────────────────────────────────
    if cves:
        story.extend(section_title("CVE Findings"))
        cve_rows = [["CVE ID", "Severity", "CVSS", "Service", "Description", "Fix"]]
        for cve in cves[:8]:
            r_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(cve.get("severity", ""), "#6b7280")
            cve_rows.append([
                Paragraph(f'<font color="#111827" size="8"><b>{cve.get("id", "")}</b></font>', ParagraphStyle("p", fontSize=8, fontName="Helvetica-Bold")),
                Paragraph(f'<font color="{r_color}" size="8"><b>{cve.get("severity", "")}</b></font>', ParagraphStyle("p", fontSize=8)),
                Paragraph(str(cve.get("cvss", "")), ParagraphStyle("p", fontSize=8)),
                Paragraph(cve.get("service", ""), ParagraphStyle("p", fontSize=8)),
                Paragraph(cve.get("desc", "")[:60], ParagraphStyle("p", fontSize=8, textColor=MUTED)),
                Paragraph(cve.get("fix", "")[:50], ParagraphStyle("p", fontSize=8, textColor=GREEN)),
            ])
        t = Table(cve_rows, colWidths=["18%", "10%", "7%", "10%", "30%", "25%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    # ── HTTP HEADERS ─────────────────────────────
    http_h = scan_result.get("http_headers", {})
    if http_h:
        story.extend(section_title(f"HTTP Security Headers — Score: {http_h.get('score', 'N/A')}"))
        h_rows = [["Header", "Status", "Value"]]
        for h in http_h.get("headers", []):
            status_color = "#16a34a" if h["present"] else "#dc2626"
            status_text = "Present" if h["present"] else "Missing"
            h_rows.append([
                Paragraph(h["name"], ParagraphStyle("p", fontSize=9)),
                Paragraph(f'<font color="{status_color}"><b>{status_text}</b></font>', ParagraphStyle("p", fontSize=9)),
                Paragraph(str(h.get("value", ""))[:50], ParagraphStyle("p", fontSize=8, textColor=MUTED)),
            ])
        t = Table(h_rows, colWidths=["40%", "15%", "45%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # ── IP GEO ───────────────────────────────────
    geo = scan_result.get("ip_geo", {})
    if geo:
        story.extend(section_title("IP Geolocation"))
        geo_rows = [
            ["IP Address", geo.get("ip", "N/A"), "Country", f'{geo.get("country", "N/A")} ({geo.get("country_code", "??")}'],
            ["City", geo.get("city", "N/A"), "Region", geo.get("region", "N/A")],
            ["ISP", geo.get("isp", "N/A"), "Organization", geo.get("org", "N/A")],
            ["Timezone", geo.get("timezone", "N/A"), "Coordinates", f'{geo.get("lat", 0)}, {geo.get("lon", 0)}'],
        ]
        t = Table([[Paragraph(f'<font color="#6b7280" size="9">{r[0]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[1]}</b></font>', ParagraphStyle("v", fontSize=9)),
                    Paragraph(f'<font color="#6b7280" size="9">{r[2]}</font>', ParagraphStyle("l", fontSize=9)),
                    Paragraph(f'<font color="#111827" size="9"><b>{r[3]}</b></font>', ParagraphStyle("v", fontSize=9))]
                   for r in geo_rows], colWidths=["18%", "32%", "18%", "32%"])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # ── ADVANCED SECTIONS ────────────────────────
    if scan_type == "advanced":

        # Subdomains
        subs = scan_result.get("subdomains", [])
        if subs:
            story.extend(section_title(f"Subdomain Finder — {len(subs)} Found"))
            sub_rows = [["Subdomain", "IP Address", "Status"]]
            for s in subs:
                sub_rows.append([s.get("subdomain", ""), s.get("ip", "N/A"), s.get("status", "Active")])
            t = Table(sub_rows, colWidths=["55%", "25%", "20%"])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
            ]))
            story.append(t)

        # Directories
        dirs = scan_result.get("directories", [])
        if dirs:
            story.extend(section_title(f"Directory Bruteforce — {len([d for d in dirs if d.get('status') == 200])} Accessible"))
            dir_rows = [["Path", "Status", "Size", "Risk", "Note"]]
            for d in dirs:
                r_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(d.get("risk", ""), "#6b7280")
                dir_rows.append([
                    Paragraph(d.get("path", ""), ParagraphStyle("p", fontSize=9, fontName="Helvetica-Bold")),
                    Paragraph(str(d.get("status", "")), ParagraphStyle("p", fontSize=9)),
                    Paragraph(d.get("size", "-"), ParagraphStyle("p", fontSize=9)),
                    Paragraph(f'<font color="{r_color}"><b>{d.get("risk", "")}</b></font>', ParagraphStyle("p", fontSize=9)),
                    Paragraph(d.get("note", ""), ParagraphStyle("p", fontSize=8, textColor=MUTED)),
                ])
            t = Table(dir_rows, colWidths=["25%", "10%", "10%", "15%", "40%"])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t)

        # CORS
        cors = scan_result.get("cors", {})
        if cors.get("vulnerable") and cors.get("issues"):
            story.extend(section_title("CORS Misconfiguration"))
            for issue in cors["issues"]:
                r_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04"}.get(issue.get("severity", ""), "#6b7280")
                story.append(p(f'<font color="{r_color}"><b>{issue.get("type", "")}</b></font> — {issue.get("detail", "")}', size=9))
                story.append(p(f'Fix: {issue.get("fix", "")}', size=9, color=GREEN))
                story.append(Spacer(1, 0.2*cm))

        # Google Dorks
        dorks = scan_result.get("dorks", [])
        if dorks:
            story.extend(section_title("Google Dork Generator"))
            for dork in dorks:
                story.append(p(f"• {dork}", size=9))

    # ── RECOMMENDATIONS ──────────────────────────
    story.extend(section_title("Recommendations"))
    recs = []
    for pt in ports:
        risk_level = pt.get("known_risk", "UNKNOWN")
        reason = pt.get("risk_reason", "")
        if risk_level in ["CRITICAL", "HIGH"]:
            recs.append((risk_level, f'Port {pt["port"]} ({pt["service"]}): {reason}'))
    for cve in cves[:5]:
        recs.append((cve.get("severity", ""), f'{cve.get("id", "")}: {cve.get("fix", "")}'))
    http_h_data = scan_result.get("http_headers", {})
    for h in http_h_data.get("headers", []):
        if not h["present"]:
            recs.append(("MEDIUM", f'Add missing header: {h["name"]}'))

    for risk_level, rec in recs[:10]:
        r_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(risk_level, "#6b7280")
        story.append(p(f'<font color="{r_color}"><b>[{risk_level}]</b></font> {rec}', size=9, color=DARK))

    # ── FOOTER ───────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        '<font color="#9ca3af" size="8">NetSentinel v1.0 — AI-Powered Network Vulnerability Scanner | '
        'Use only on networks you own or have explicit written permission to test. '
        'Unauthorized scanning is illegal.</font>',
        ParagraphStyle("footer", fontSize=8, textColor=MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    return path
