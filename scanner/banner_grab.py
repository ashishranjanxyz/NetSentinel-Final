import socket

def banner_grab(target, port_data):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    banners = []
    
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = domain

    for port_info in port_data[:8]:
        port = port_info["port"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            if port in [80, 8080, 8443]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + domain.encode() + b"\r\n\r\n")
            elif port == 21:
                pass
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            if banner:
                banner_line = banner.split('\n')[0][:120]
                banners.append({"port": port, "banner": banner_line})
        except Exception:
            # Use known service info as fallback
            svc = port_info.get("product", "") + " " + port_info.get("version", "")
            if svc.strip():
                banners.append({"port": port, "banner": svc.strip()})

    return banners
