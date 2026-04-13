import requests, socket

def asn_lookup(target):
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
        if r.status_code == 200:
            parts = r.text.strip().strip('"').split(",")
            if len(parts) >= 4:
                return {
                    "ip": ip,
                    "asn": parts[0].strip().strip('"'),
                    "ip_range": parts[1].strip().strip('"'),
                    "country": parts[2].strip().strip('"'),
                    "org": parts[3].strip().strip('"'),
                }
    except Exception:
        pass

    try:
        r2 = requests.get(f"http://ip-api.com/json/{ip}?fields=as,org,isp,country", timeout=8)
        data = r2.json()
        return {
            "ip": ip,
            "asn": data.get("as", "Unknown"),
            "ip_range": "N/A",
            "country": data.get("country", "Unknown"),
            "org": data.get("org", data.get("isp", "Unknown")),
        }
    except Exception:
        pass

    return {"ip": target, "asn": "N/A", "ip_range": "N/A", "country": "Unknown", "org": "Unknown"}
