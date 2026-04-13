import requests, socket

def ip_geo_lookup(target):
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,lat,lon,timezone,as", timeout=8)
        data = r.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "timezone": data.get("timezone", "Unknown"),
                "asn": data.get("as", "Unknown"),
            }
    except Exception as e:
        pass

    return {
        "ip": target,
        "country": "Unknown",
        "country_code": "??",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "lat": 0, "lon": 0,
        "timezone": "Unknown",
        "asn": "Unknown",
    }
