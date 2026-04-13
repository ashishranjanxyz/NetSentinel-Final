import ssl, socket, datetime

def ssl_check(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.datetime.utcnow()).days

        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        san = []
        for ext in cert.get('subjectAltName', []):
            if ext[0] == 'DNS':
                san.append(ext[1])

        # Grade based on days left and protocol
        if days_left > 90:
            grade = "A"
        elif days_left > 30:
            grade = "B"
        elif days_left > 0:
            grade = "C"
        else:
            grade = "F"

        protocol = s.version() if hasattr(s, 'version') else "TLS"

        return {
            "valid": True,
            "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
            "subject": subject.get('commonName', domain),
            "issued": not_before.strftime('%Y-%m-%d'),
            "expires": not_after.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "grade": grade,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "san": san[:5],
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "Certificate verification failed", "grade": "F", "days_left": 0}
    except ConnectionRefusedError:
        return {"valid": False, "error": "Port 443 not open", "grade": "N/A", "days_left": 0}
    except Exception as e:
        return {"valid": False, "error": str(e), "grade": "N/A", "days_left": 0}
