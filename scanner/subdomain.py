import socket
import concurrent.futures

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "staging", "api", "admin", "blog", "test", "secure", "vpn", "m",
    "shop", "remote", "portal", "beta", "cdn", "static", "assets", "media",
    "app", "apps", "auth", "login", "dashboard", "cloud", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "docs", "support", "help",
    "status", "monitor", "backup", "old", "new", "demo", "sandbox",
]

def check_subdomain(domain, sub):
    full = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return {"subdomain": full, "ip": ip, "status": "Active"}
    except Exception:
        return None

def subdomain_finder(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    # Remove www prefix if present
    if domain.startswith("www."):
        domain = domain[4:]

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, domain, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])
