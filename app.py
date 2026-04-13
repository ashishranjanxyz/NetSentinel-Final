from flask import Flask, render_template, request, jsonify, send_file
import json, datetime, os, sys, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.port_scanner import PortScanner
from scanner.whois_lookup import whois_lookup
from scanner.dns_lookup import dns_lookup
from scanner.ssl_checker import ssl_check
from scanner.ip_geo import ip_geo_lookup
from scanner.http_headers import check_http_headers
from scanner.banner_grab import banner_grab
from scanner.reverse_dns import reverse_dns_lookup
from scanner.cve_scanner import cve_scan
from scanner.subdomain import subdomain_finder
from scanner.tech_detect import detect_technologies
from scanner.cors_check import cors_check
from scanner.dork_gen import generate_dorks
from scanner.reverse_ip import reverse_ip_lookup
from scanner.asn_lookup import asn_lookup
from scanner.dir_brute import dir_bruteforce
from ml.model import NetSentinelAI
from report.pdf_report import generate_pdf

app = Flask(__name__)
ai_engine = NetSentinelAI()

# In-memory scan history and live stats
scan_history = []
total_scans = 12840
live_scans = 0
lock = threading.Lock()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    global total_scans, live_scans
    return jsonify({
        'total_scans': total_scans,
        'today_scans': 247 + (total_scans - 12840),
        'live_scans': live_scans,
        'recent_scans': scan_history[-5:][::-1]
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    global total_scans, live_scans
    data = request.get_json()
    target = data.get('target', '').strip()
    ports = data.get('ports', '1-1024')
    scan_type = data.get('type', 'basic')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    with lock:
        live_scans += 1

    try:
        result = run_scan(target, ports, scan_type)

        with lock:
            total_scans += 1
            live_scans = max(0, live_scans - 1)
            scan_history.append({
                'target': target,
                'risk': result.get('ai', {}).get('risk_level', 'UNKNOWN'),
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
                'country': result.get('ip_geo', {}).get('country_code', 'UN'),
                'ports': len(result.get('port_scan', {}).get('ports', []))
            })
            if len(scan_history) > 50:
                scan_history.pop(0)

        return jsonify({'success': True, 'target': target, 'scan_type': scan_type, 'result': result})

    except Exception as e:
        with lock:
            live_scans = max(0, live_scans - 1)
        return jsonify({'error': str(e)}), 500

def run_scan(target, ports, scan_type):
    result = {}
    scanner = PortScanner()

    # 1. Port Scan + AI
    port_data = scanner.scan(target, ports)
    feature_vec = scanner.get_feature_vector(port_data)
    ai_result = ai_engine.analyze(feature_vec, port_data)
    result['port_scan'] = {'ports': port_data, 'ai': ai_result}

    # 2. WHOIS
    result['whois'] = whois_lookup(target)

    # 3. DNS
    result['dns'] = dns_lookup(target)

    # 4. SSL
    result['ssl'] = ssl_check(target)

    # 5. IP Geo
    result['ip_geo'] = ip_geo_lookup(target)

    # 6. CVE
    result['cve'] = cve_scan(port_data)

    # 7. HTTP Headers
    result['http_headers'] = check_http_headers(target)

    # 8. Banner Grab
    result['banner'] = banner_grab(target, port_data)

    # 9. Reverse DNS
    result['reverse_dns'] = reverse_dns_lookup(target)

    # Advanced only
    if scan_type == 'advanced':
        result['subdomains'] = subdomain_finder(target)
        result['tech_stack'] = detect_technologies(target)
        result['cors'] = cors_check(target)
        result['dorks'] = generate_dorks(target)
        result['reverse_ip'] = reverse_ip_lookup(target)
        result['asn'] = asn_lookup(target)
        result['directories'] = dir_bruteforce(target)

    return result

@app.route('/api/pdf', methods=['POST'])
def download_pdf():
    data = request.get_json()
    target = data.get('target', 'unknown')
    scan_result = data.get('result', {})
    scan_type = data.get('scan_type', 'basic')

    pdf_path = generate_pdf(target, scan_result, scan_type)
    return send_file(pdf_path, as_attachment=True, download_name=f'netsentinel_{target}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
