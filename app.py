from flask import Flask, jsonify, render_template
from analyzer import analyze_logs
from geo import get_location
import datetime

app = Flask(__name__)

# 🔥 API for live updates
@app.route("/data")
def data():
    real_data, fake_data, suspicious, time_series = analyze_logs()

    now = datetime.datetime.now()
    # Generate 5 minutes of mock timeline labels and values
    mock_labels = [(now - datetime.timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M") for i in range(4, -1, -1)]
    mock_values_fixed = [12, 45, 20, 60, 30]
    
    # We want to represent the timeline with both static & real data over the same labels.
    # Start with our mock labels, then add any real labels, keep them sorted.
    all_time_labels = sorted(list(set(mock_labels) | set(time_series.keys())))
    
    mock_time_values = []
    real_time_values = []
    for label in all_time_labels:
        # For mock data representation, if it's one of the mock labels, assign its static value, otherwise 0
        if label in mock_labels:
            mock_time_values.append(mock_values_fixed[mock_labels.index(label)])
        else:
            mock_time_values.append(0)
            
        # Real data gets whatever was seen in logs
        real_time_values.append(time_series.get(label, 0))

    # Top attackers logic: if empty, show a simulated one so UI is never fully empty
    top_attackers = sorted(real_data.items(), key=lambda x: x[1], reverse=True)[:3]
    if not top_attackers:
        top_attackers = [("Simulated (192.168.x.x)", 45), ("Simulated (10.0.x.x)", 22)]

    # We also keep some simulated dots on the map and distribution if everything is empty
    if not real_data and not fake_data:
        real_data = {"192.168.1.100": 45, "10.0.0.8": 22, "172.16.0.4": 15}
        fake_data = {"192.168.1.10": 10, "10.0.0.5": 25, "172.16.0.3": 5}
        # Clear out suspicious array so we don't trigger the red alert for mock data
        suspicious = []

    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    locations = {}
    for ip in real_data:
        if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16"):
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

    return jsonify({
        "ips": all_ips,
        "real": real_values,
        "fake": fake_values,
        "time_labels": all_time_labels,
        "mock_time_values": mock_time_values,
        "real_time_values": real_time_values,
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
    app.run(host="0.0.0.0", debug=True, port=5001)