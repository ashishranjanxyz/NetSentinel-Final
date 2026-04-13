CVE_DATABASE = {
    "openssh": [
        {"id": "CVE-2024-6387", "severity": "CRITICAL", "cvss": 9.8, "desc": "RegreSSHion — Unauthenticated Remote Code Execution in OpenSSH", "fix": "Update to OpenSSH 9.8p1 or later"},
        {"id": "CVE-2023-38408", "severity": "CRITICAL", "cvss": 9.8, "desc": "Remote code execution via ssh-agent PKCS#11 provider", "fix": "Update to OpenSSH 9.3p2 or later"},
    ],
    "apache": [
        {"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "desc": "Log4Shell — Remote Code Execution via JNDI injection in Apache Log4j", "fix": "Update Log4j to 2.17.1 or later"},
        {"id": "CVE-2021-41773", "severity": "HIGH", "cvss": 7.5, "desc": "Path traversal and RCE in Apache HTTP Server 2.4.49", "fix": "Update to Apache 2.4.51 or later"},
    ],
    "nginx": [
        {"id": "CVE-2021-23017", "severity": "HIGH", "cvss": 7.7, "desc": "Off-by-one heap write in nginx DNS resolver", "fix": "Update to nginx 1.21.0 or later"},
    ],
    "mysql": [
        {"id": "CVE-2022-21702", "severity": "HIGH", "cvss": 7.5, "desc": "MySQL Server privilege escalation vulnerability", "fix": "Update to MySQL 8.0.28 or later"},
    ],
    "smb": [
        {"id": "CVE-2017-0144", "severity": "CRITICAL", "cvss": 9.3, "desc": "EternalBlue — SMBv1 Remote Code Execution (WannaCry vector)", "fix": "Apply MS17-010 patch, disable SMBv1"},
        {"id": "CVE-2020-1472", "severity": "CRITICAL", "cvss": 10.0, "desc": "Zerologon — Authentication bypass in Netlogon", "fix": "Apply MS20-049 security update immediately"},
    ],
    "rdp": [
        {"id": "CVE-2019-0708", "severity": "CRITICAL", "cvss": 9.8, "desc": "BlueKeep — Wormable RCE in Remote Desktop Services", "fix": "Apply MS19-0708 patch immediately"},
    ],
    "ftp": [
        {"id": "CVE-2010-4221", "severity": "HIGH", "cvss": 7.5, "desc": "Buffer overflow in ProFTPD mod_sql module", "fix": "Update ProFTPD to latest version"},
    ],
    "telnet": [
        {"id": "CVE-2020-10188", "severity": "CRITICAL", "cvss": 9.8, "desc": "Arbitrary code execution in telnetd", "fix": "Disable Telnet immediately, use SSH instead"},
    ],
}

SERVICE_MAP = {
    22: ["openssh", "ssh"],
    80: ["apache", "nginx", "http"],
    443: ["apache", "nginx", "https"],
    445: ["smb"],
    3389: ["rdp"],
    21: ["ftp"],
    23: ["telnet"],
    3306: ["mysql"],
    8080: ["apache", "nginx"],
}

def cve_scan(port_data):
    found_cves = []
    seen_ids = set()

    for port_info in port_data:
        port = port_info.get("port", 0)
        service = port_info.get("service", "").lower()
        product = port_info.get("product", "").lower()
        version = port_info.get("version", "").lower()
        combined = f"{service} {product} {version}"

        keys_to_check = SERVICE_MAP.get(port, [])
        for key in CVE_DATABASE.keys():
            if key in combined:
                if key not in keys_to_check:
                    keys_to_check.append(key)

        for key in keys_to_check:
            cves = CVE_DATABASE.get(key, [])
            for cve in cves:
                if cve["id"] not in seen_ids:
                    seen_ids.add(cve["id"])
                    found_cves.append({**cve, "service": port_info.get("service", key), "port": port})

    found_cves.sort(key=lambda x: x["cvss"], reverse=True)
    return found_cves
