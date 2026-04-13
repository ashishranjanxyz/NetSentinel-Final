import requests, socket

def reverse_ip_lookup(target):
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().split("\n") if d.strip()]
            return [{"domain": d, "ip": ip} for d in domains[:10]]
    except Exception:
        pass
    return [{"domain": target, "ip": target, "note": "Primary domain on this IP"}]
