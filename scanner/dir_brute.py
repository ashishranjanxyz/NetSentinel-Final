import requests, concurrent.futures

COMMON_DIRS = [
    "/.git", "/.env", "/backup", "/admin", "/phpinfo.php", "/wp-admin",
    "/config", "/.htaccess", "/robots.txt", "/sitemap.xml", "/api",
    "/login", "/dashboard", "/.svn", "/test", "/debug", "/logs",
    "/uploads", "/files", "/data", "/db", "/database", "/sql",
    "/wp-config.php", "/config.php", "/.DS_Store", "/server-status",
]

RISK_MAP = {
    "/.git": "CRITICAL", "/.env": "CRITICAL", "/wp-config.php": "CRITICAL",
    "/config.php": "CRITICAL", "/backup": "HIGH", "/db": "HIGH",
    "/database": "HIGH", "/sql": "HIGH", "/admin": "MEDIUM",
    "/phpinfo.php": "HIGH", "/debug": "HIGH", "/logs": "HIGH",
    "/uploads": "MEDIUM", "/test": "LOW", "/robots.txt": "LOW",
    "/sitemap.xml": "LOW", "/.DS_Store": "MEDIUM",
}

def check_dir(base_url, path):
    try:
        r = requests.get(base_url + path, timeout=5, verify=False, allow_redirects=False)
        if r.status_code in [200, 403, 301, 302]:
            size = f"{len(r.content) / 1024:.1f}KB" if r.status_code == 200 else "-"
            return {
                "path": path,
                "status": r.status_code,
                "size": size,
                "risk": RISK_MAP.get(path, "LOW"),
                "note": "Accessible" if r.status_code == 200 else ("Exists (Forbidden)" if r.status_code == 403 else "Redirects")
            }
    except Exception:
        pass
    return None

def dir_bruteforce(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    base_url = f"https://{domain}"
    found = []

    try:
        requests.get(base_url, timeout=5, verify=False)
    except Exception:
        base_url = f"http://{domain}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_dir, base_url, path): path for path in COMMON_DIRS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(found, key=lambda x: risk_order.get(x["risk"], 4))
