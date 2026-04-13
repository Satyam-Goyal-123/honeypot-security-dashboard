import requests

def get_location(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url).json()

        if response["status"] == "success":
            return {
                "country": response["country"],
                "city": response["city"],
                "lat": response["lat"],
                "lon": response["lon"]
            }
    except:
        pass

    return None