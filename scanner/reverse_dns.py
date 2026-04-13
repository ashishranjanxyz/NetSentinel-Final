import socket

def reverse_dns_lookup(target):
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        hostname = socket.gethostbyaddr(ip)[0]
        match = hostname == domain or domain in hostname
        return {
            "ip": ip,
            "hostname": hostname,
            "ptr_record": hostname,
            "match": match,
            "status": "Valid — PTR record matches forward DNS" if match else "Mismatch — possible spoofing"
        }
    except Exception as e:
        return {"ip": target, "hostname": "N/A", "ptr_record": "N/A", "match": False, "status": str(e)}
