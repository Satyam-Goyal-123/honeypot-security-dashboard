from flask import Flask, jsonify, render_template
from analyzer import analyze_logs
from geo import get_location
import datetime

app = Flask(__name__)

# 🔥 API for live updates
@app.route("/data")
def data():
    real_data, fake_data, suspicious, time_series = analyze_logs()

    # If there's no data yet (e.g. fresh start), send some simulated/static data
    # so the dashboard doesn't look empty and boring.
    if not real_data and not fake_data:
        now = datetime.datetime.now()
        # Mocking time_series for the last few minutes
        time_series = {
            (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"): 12,
            (now - datetime.timedelta(minutes=4)).strftime("%Y-%m-%d %H:%M"): 45,
            (now - datetime.timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M"): 20,
            (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M"): 60,
            (now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M"): 30,
        }
        
        real_data = {"192.168.1.100": 45, "10.0.0.8": 22, "172.16.0.4": 15}
        fake_data = {"192.168.1.10": 10, "10.0.0.5": 25, "172.16.0.3": 5}
        suspicious = ["192.168.1.100", "10.0.0.8"]

    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    locations = {}
    for ip in real_data:
        # Avoid local IPs from trying to resolve via ip-api
        if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16"):
            # Mock locations for local IPs just for the visual effect
            import random
            locations[ip] = {
                "lat": random.uniform(-60, 60), 
                "lon": random.uniform(-120, 120),
                "city": "Simulated City",
                "country": "Simulated Country"
            }
        else:
            loc = get_location(ip)
            if loc:
                locations[ip] = loc

    top_attackers = sorted(real_data.items(), key=lambda x: x[1], reverse=True)[:3]

    return jsonify({
        "ips": all_ips,
        "real": real_values,
        "fake": fake_values,
        "time_labels": list(time_series.keys()),
        "time_values": list(time_series.values()),
        "suspicious": suspicious,
        "locations": locations,
        "top": top_attackers,
        "rate": sum(time_series.values())
    })


# 🔥 MAIN UI
@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)