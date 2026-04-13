import requests

def detect_technologies(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    detected = []

    for url in [f"https://{domain}", f"http://{domain}"]:
        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            body = r.text.lower()

            checks = [
                ("X-Powered-By", "x-powered-by", "Backend", headers),
                ("Server", "server", "Web Server", headers),
            ]
            for name, key, cat, src in checks:
                val = src.get(key, "")
                if val:
                    detected.append({"name": val.split("/")[0].strip().title(), "category": cat})

            tech_signatures = [
                ("WordPress", "wp-content", "CMS"),
                ("Joomla", "joomla", "CMS"),
                ("Drupal", "drupal", "CMS"),
                ("jQuery", "jquery", "JS Library"),
                ("React", "react", "JS Framework"),
                ("Vue.js", "vue.js", "JS Framework"),
                ("Angular", "ng-version", "JS Framework"),
                ("Bootstrap", "bootstrap", "CSS Framework"),
                ("Laravel", "laravel", "PHP Framework"),
                ("Django", "django", "Python Framework"),
                ("Google Analytics", "google-analytics", "Analytics"),
                ("Google Tag Manager", "googletagmanager", "Analytics"),
                ("Cloudflare", "cloudflare", "CDN/Security"),
                ("AWS", "aws", "Cloud"),
                ("PHP", "php", "Language"),
            ]
            for name, sig, cat in tech_signatures:
                if sig in body or sig in str(headers):
                    if not any(d["name"] == name for d in detected):
                        detected.append({"name": name, "category": cat})

            break
        except Exception:
            continue

    return detected[:12] if detected else [{"name": "Could not detect", "category": "N/A"}]
