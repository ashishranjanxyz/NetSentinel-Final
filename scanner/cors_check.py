import requests

def cors_check(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    issues = []
    vulnerable = False

    test_origins = ["https://evil.com", "null", f"https://fake.{domain}"]

    for url in [f"https://{domain}", f"http://{domain}"]:
        for origin in test_origins:
            try:
                r = requests.get(url, headers={"Origin": origin}, timeout=8, verify=False, allow_redirects=True)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    vulnerable = True
                    issues.append({
                        "type": "Wildcard Origin Allowed",
                        "severity": "HIGH",
                        "detail": "Access-Control-Allow-Origin: *",
                        "fix": "Replace wildcard with specific trusted origins"
                    })

                if acao == origin and origin == "https://evil.com":
                    vulnerable = True
                    issues.append({
                        "type": "Arbitrary Origin Reflected",
                        "severity": "HIGH",
                        "detail": f"Server reflects attacker origin: {origin}",
                        "fix": "Implement strict origin whitelist validation"
                    })

                if acao == "*" and acac.lower() == "true":
                    issues.append({
                        "type": "Wildcard with Credentials",
                        "severity": "CRITICAL",
                        "detail": "Wildcard origin combined with Allow-Credentials: true",
                        "fix": "Never combine wildcard with credentials — browsers reject but still a misconfiguration"
                    })

                if acao == "null":
                    vulnerable = True
                    issues.append({
                        "type": "Null Origin Accepted",
                        "severity": "MEDIUM",
                        "detail": "Server accepts null origin which can be set by sandboxed iframes",
                        "fix": "Remove null from allowed origins whitelist"
                    })

            except Exception:
                continue

        break

    seen = set()
    unique_issues = []
    for issue in issues:
        if issue["type"] not in seen:
            seen.add(issue["type"])
            unique_issues.append(issue)

    return {"vulnerable": vulnerable, "issues": unique_issues}
