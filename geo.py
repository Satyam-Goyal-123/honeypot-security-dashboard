import requests

CACHE = {}

def get_location(ip):
    if ip in CACHE:
        return CACHE[ip]

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            geo_data = {
                "lat": res.get("lat"),
                "lon": res.get("lon"),
                "city": res.get("city"),
                "country": res.get("country")
            }
            CACHE[ip] = geo_data
            return geo_data
        else:
            CACHE[ip] = None
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}")
        CACHE[ip] = None
        
    return CACHE[ip]