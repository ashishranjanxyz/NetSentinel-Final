import nmap, socket, datetime

KNOWN_RISKY_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "reason": "Plaintext auth, anonymous login possible"},
    22: {"service": "SSH", "risk": "MEDIUM", "reason": "Brute force target, ensure key-based auth"},
    23: {"service": "Telnet", "risk": "CRITICAL", "reason": "Plaintext protocol, completely insecure"},
    25: {"service": "SMTP", "risk": "MEDIUM", "reason": "Open relay abuse, spam vector"},
    53: {"service": "DNS", "risk": "MEDIUM", "reason": "DNS amplification DDoS attacks"},
    80: {"service": "HTTP", "risk": "LOW", "reason": "Unencrypted web traffic"},
    110: {"service": "POP3", "risk": "HIGH", "reason": "Plaintext email retrieval"},
    135: {"service": "MSRPC", "risk": "HIGH", "reason": "Windows RPC exploitation vector"},
    139: {"service": "NetBIOS", "risk": "HIGH", "reason": "Information disclosure risk"},
    143: {"service": "IMAP", "risk": "MEDIUM", "reason": "Plaintext email access"},
    443: {"service": "HTTPS", "risk": "LOW", "reason": "Encrypted web traffic"},
    445: {"service": "SMB", "risk": "CRITICAL", "reason": "WannaCry/EternalBlue vector"},
    1433: {"service": "MSSQL", "risk": "HIGH", "reason": "Direct database exposure"},
    1521: {"service": "Oracle DB", "risk": "HIGH", "reason": "Direct database exposure"},
    3306: {"service": "MySQL", "risk": "HIGH", "reason": "Database publicly exposed"},
    3389: {"service": "RDP", "risk": "CRITICAL", "reason": "BlueKeep, brute force target"},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "reason": "Database publicly exposed"},
    5900: {"service": "VNC", "risk": "CRITICAL", "reason": "Often unauthenticated remote desktop"},
    6379: {"service": "Redis", "risk": "CRITICAL", "reason": "No authentication by default"},
    8080: {"service": "HTTP-Alt", "risk": "MEDIUM", "reason": "Development server exposed"},
    8443: {"service": "HTTPS-Alt", "risk": "LOW", "reason": "Alternate HTTPS port"},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "reason": "No authentication by default"},
}

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def validate_target(self, target):
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

    def scan(self, target, port_range="1-1024"):
        if not self.validate_target(target):
            raise ValueError(f"Cannot resolve target: {target}")
        try:
            self.nm.scan(hosts=target, ports=port_range, arguments="-sV --open -T3")
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap error: {e}")

        ports = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    info = self.nm[host][proto][port]
                    if info["state"] == "open":
                        known = KNOWN_RISKY_PORTS.get(port, {})
                        ports.append({
                            "port": port,
                            "protocol": proto,
                            "service": info.get("name", "unknown"),
                            "version": info.get("version", ""),
                            "product": info.get("product", ""),
                            "state": "open",
                            "known_risk": known.get("risk", "UNKNOWN"),
                            "risk_reason": known.get("reason", "Not in known vulnerability database"),
                        })
        return ports

    def get_feature_vector(self, port_data):
        if not port_data:
            return [0, 0, 0, 0, 0, 0]
        critical_ports = {23, 445, 3389, 5900, 6379, 27017}
        db_ports = {1433, 1521, 3306, 5432, 27017, 6379}
        remote_access = {22, 23, 3389, 5900}
        legacy = {21, 23, 110, 139}
        open_set = {p["port"] for p in port_data}
        risk_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
        risk_score = sum(risk_map.get(p.get("known_risk", "UNKNOWN"), 1) for p in port_data)
        return [
            len(port_data),
            int(bool(open_set & critical_ports)),
            int(bool(open_set & db_ports)),
            int(bool(open_set & remote_access)),
            int(bool(open_set & legacy)),
            risk_score
        ]
