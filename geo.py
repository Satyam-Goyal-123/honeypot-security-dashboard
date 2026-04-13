import requests

def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res["status"] == "success":
            return {
                "lat": res["lat"],
                "lon": res["lon"],
                "city": res["city"],
                "country": res["country"]
            }
    except:
        pass
    return None