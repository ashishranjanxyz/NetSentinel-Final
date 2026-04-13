# NetSentinel — AI-Powered Network Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?style=for-the-badge&logo=scikitlearn)
![Nmap](https://img.shields.io/badge/Scanner-Nmap-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

**A full-stack AI-powered network vulnerability scanner with 20 security modules, real-time threat analysis, and professional PDF reporting.**

[Live Demo](https://netsentinel-final.onrender.com) · [Report Bug](https://github.com/ashishranjanxyz/NetSentinel-Final/issues) · [LinkedIn](https://linkedin.com/in/ashishranjanxyz)

</div>

---

## What is NetSentinel?

NetSentinel is a web-based penetration testing tool that combines Nmap with Machine Learning to provide intelligent network vulnerability assessment. Built solo from scratch — no team, no tutorial.

It goes beyond traditional port scanning by using AI models to classify risk levels and detect anomalous behavior in network profiles.

---

## Features

### Basic Scan — 10 Modules
| Module | Description |
|--------|-------------|
| Port Scanner + AI | Open port detection with Random Forest risk classification |
| WHOIS Lookup | Domain registration and ownership intel |
| DNS Records | Full DNS analysis — A, MX, TXT, NS, CNAME, SOA |
| SSL Certificate | Certificate health, grade, expiry, cipher suite |
| CVE Scanner | Matches open services against known CVE database |
| HTTP Security Headers | Checks for HSTS, CSP, X-Frame and more |
| Banner Grabbing | Raw service banner extraction |
| Reverse DNS | PTR record verification |
| IP Geolocation | Country, city, ISP, coordinates |
| PDF Report | Professional downloadable vulnerability report |

### Advanced Scan — 20 Modules
Everything in Basic, plus:

| Module | Description |
|--------|-------------|
| Subdomain Finder | Enumerates hidden subdomains |
| Technology Detection | Identifies web stack — CMS, frameworks, servers |
| CORS Misconfiguration | Detects wildcard and credential CORS issues |
| Google Dork Generator | Passive recon query generation |
| Reverse IP Lookup | Finds all domains on the same IP |
| ASN Lookup | Network ownership and IP range info |
| Directory Bruteforce | Finds exposed paths and sensitive files |
| Shodan Integration | Cross-references with Shodan intelligence |
| Comparison Mode | Side-by-side scan of 2 targets |
| Scan History | Tracks previous scan results |

---

## AI Architecture

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Risk Classifier | Random Forest (100 trees) | Classifies host risk: LOW / MEDIUM / HIGH |
| Anomaly Detector | Isolation Forest | Flags unusual port combinations vs normal baseline |

### Feature Vector
```
[num_open_ports, has_critical_ports, has_db_ports,
 has_remote_access, has_legacy_services, total_risk_score]
```

---

## Screenshots

> Landing page with live scan dashboard, threat map, and 20-module feature grid.
> Results page with full AI analysis, CVE findings, and PDF download.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask |
| Scanner | python-nmap (Nmap wrapper) |
| Machine Learning | scikit-learn — Random Forest, Isolation Forest |
| DNS | dnspython |
| WHOIS | python-whois |
| PDF Generation | ReportLab |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Deployment | Railway / Docker |

---

## Run Locally

### Prerequisites
- Python 3.11+
- Nmap installed → [nmap.org/download](https://nmap.org/download.html)

### Installation

```bash
git clone https://github.com/ashishranjanxyz/NetSentinel-Final.git
cd NetSentinel-Final
pip install -r requirements.txt
python app.py
```

Open browser: `http://localhost:5000`

---

## Project Structure

```
NetSentinel-Final/
├── app.py                      # Flask backend + API routes
├── scanner/
│   ├── port_scanner.py         # Nmap wrapper + feature extraction
│   ├── whois_lookup.py         # WHOIS module
│   ├── dns_lookup.py           # DNS records module
│   ├── ssl_checker.py          # SSL certificate checker
│   ├── ip_geo.py               # IP geolocation
│   ├── http_headers.py         # HTTP security headers
│   ├── banner_grab.py          # Banner grabbing
│   ├── reverse_dns.py          # Reverse DNS lookup
│   ├── cve_scanner.py          # CVE database matching
│   ├── subdomain.py            # Subdomain enumeration
│   ├── tech_detect.py          # Technology detection
│   ├── cors_check.py           # CORS misconfiguration
│   ├── dork_gen.py             # Google dork generator
│   ├── reverse_ip.py           # Reverse IP lookup
│   ├── asn_lookup.py           # ASN lookup
│   └── dir_brute.py            # Directory bruteforce
├── ml/
│   └── model.py                # Random Forest + Isolation Forest
├── report/
│   └── pdf_report.py           # PDF report generator
├── templates/
│   └── index.html              # Full frontend
├── static/
│   └── ashish.png              # Developer photo
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## API

### POST `/api/scan`
```json
{
  "target": "scanme.nmap.org",
  "ports": "1-1024",
  "type": "basic"
}
```

### POST `/api/pdf`
```json
{
  "target": "scanme.nmap.org",
  "result": {},
  "scan_type": "basic"
}
```

### GET `/api/stats`
Returns live scan statistics and recent scan history.

---

## Legal Disclaimer

> **NetSentinel is for authorized security testing only.**
>
> Only use this tool on networks you own or have explicit written permission to test.
> Unauthorized port scanning may be illegal in your jurisdiction.
> The author assumes no liability for misuse.

---

## About the Developer

Built by **Ashish Ranjan** — Cybersecurity Researcher, Ethical Hacker, B.Tech CSE.

- Top 1% on TryHackMe — India, Wall of Fame
- 700+ rooms solved, 68+ badges earned
- Interned with Deloitte, Mastercard & Tata
- Certified by Cisco, Microsoft, ISC2 & Cybrary

[GitHub](https://github.com/ashishranjanxyz) · [LinkedIn](https://linkedin.com/in/ashishranjanxyz) · [Instagram](https://instagram.com/ashishranjanxyz)

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">

**If this project helped you, consider giving it a star!**

</div>