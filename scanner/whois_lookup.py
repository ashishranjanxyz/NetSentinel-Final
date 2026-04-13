import whois as python_whois

def whois_lookup(target):
    try:
        # Strip protocol if present
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        w = python_whois.whois(domain)
        
        def safe_str(val):
            if isinstance(val, list):
                return str(val[0]) if val else "N/A"
            return str(val) if val else "N/A"

        def safe_date(val):
            if isinstance(val, list):
                val = val[0]
            if val and hasattr(val, 'strftime'):
                return val.strftime('%Y-%m-%d')
            return str(val)[:10] if val else "N/A"

        return {
            "domain": domain,
            "registrar": safe_str(w.registrar),
            "created": safe_date(w.creation_date),
            "expires": safe_date(w.expiration_date),
            "updated": safe_date(w.updated_date),
            "status": safe_str(w.status),
            "name_servers": [str(ns) for ns in (w.name_servers or [])][:4],
            "country": safe_str(w.country),
            "org": safe_str(getattr(w, 'org', None)),
        }
    except Exception as e:
        return {
            "domain": target,
            "registrar": "N/A",
            "created": "N/A",
            "expires": "N/A",
            "updated": "N/A",
            "status": "N/A",
            "name_servers": [],
            "country": "N/A",
            "org": "N/A",
            "error": str(e)
        }
