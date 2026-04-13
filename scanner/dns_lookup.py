import dns.resolver

def dns_lookup(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == 'MX':
                results[rtype] = [f"{r.preference} {r.exchange}" for r in answers]
            elif rtype == 'SOA':
                for r in answers:
                    results[rtype] = f"{r.mname} {r.rname}"
                    break
            else:
                results[rtype] = [r.to_text() for r in answers]
        except Exception:
            pass

    return results if results else {"error": "No DNS records found"}
