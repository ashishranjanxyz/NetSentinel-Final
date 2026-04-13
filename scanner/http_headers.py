import requests

SECURITY_HEADERS = [
    {"name": "Strict-Transport-Security", "key": "strict-transport-security", "weight": 20},
    {"name": "Content-Security-Policy", "key": "content-security-policy", "weight": 25},
    {"name": "X-Frame-Options", "key": "x-frame-options", "weight": 15},
    {"name": "X-Content-Type-Options", "key": "x-content-type-options", "weight": 10},
    {"name": "Referrer-Policy", "key": "referrer-policy", "weight": 10},
    {"name": "Permissions-Policy", "key": "permissions-policy", "weight": 10},
    {"name": "X-XSS-Protection", "key": "x-xss-protection", "weight": 10},
]

def check_http_headers(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    urls = [f"https://{domain}", f"http://{domain}"]
    headers = {}

    for url in urls:
        try:
            r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in r.headers.items()}
            break
        except Exception:
            continue

    if not headers:
        return {"score": "F", "headers": [{"name": h["name"], "present": False, "value": "Could not connect"} for h in SECURITY_HEADERS]}

    result_headers = []
    score = 0
    for h in SECURITY_HEADERS:
        present = h["key"] in headers
        if present:
            score += h["weight"]
        result_headers.append({
            "name": h["name"],
            "present": present,
            "value": headers.get(h["key"], "Missing")
        })

    if score >= 85:
        grade = "A+"
    elif score >= 70:
        grade = "A"
    elif score >= 55:
        grade = "B"
    elif score >= 40:
        grade = "C+"
    elif score >= 25:
        grade = "C"
    else:
        grade = "D"

    return {"score": grade, "headers": result_headers, "raw_score": score}
