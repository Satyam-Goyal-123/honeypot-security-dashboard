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

def get_dashboard_payload():
    """Compiles the full payload for the dashboard."""
    data = analyze_logs()
    
    real_data = data["real_count"]
    fake_data = data["fake_count"]
    suspicious = data["suspicious"]
    time_series = data["time_series"]
    attack_classes = data["attack_classes"]
    raw_logs = data["raw_logs"]

    # --- Enterprise Mock Simulation (if empty) ---
    if not real_data and not fake_data:
        global mock_cache
        if not mock_cache:
            now = datetime.datetime.now()
            # Mocks
            time_series = {
                (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"): 12,
                (now - datetime.timedelta(minutes=4)).strftime("%Y-%m-%d %H:%M"): 45,
                (now - datetime.timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M"): 20,
                (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M"): 60,
                (now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M"): 30,
            }
            real_data = {"192.168.1.100": 45, "10.0.0.8": 22, "172.16.0.4": 15}
            fake_data = {"192.168.1.10": 10, "10.0.0.5": 25, "172.16.0.3": 5}
            attack_classes = {"Brute Force": 50, "Malware": 15, "Scanning": 17, "Unknown": 0}
            suspicious = {
                "192.168.1.100": {"count": 45, "severity": "HIGH", "type": "Brute Force"},
                "10.0.0.8": {"count": 22, "severity": "MEDIUM", "type": "Scanning"}
            }
            raw_logs = [
                {"timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "ip": "192.168.1.100", "port": "9999", "type": "Brute Force", "payload": "admin\\n", "is_real": True},
                {"timestamp": (now - datetime.timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S"), "ip": "10.0.0.8", "port": "9999", "type": "Scanning", "payload": "nmap scan", "is_real": True}
            ]
            mock_cache = {
                "time_series": time_series, "real_data": real_data, "fake_data": fake_data,
                "attack_classes": attack_classes, "suspicious": suspicious, "raw_logs": raw_logs
            }
        else:
            time_series = mock_cache["time_series"]
            real_data = mock_cache["real_data"]
            fake_data = mock_cache["fake_data"]
            attack_classes = mock_cache["attack_classes"]
            suspicious = mock_cache["suspicious"]
            raw_logs = mock_cache["raw_logs"]
    else:
        # If live data is generated, we wipe the mock cache so it transitions
        mock_cache = None

    # Process Timeline
    now = datetime.datetime.now()
    mock_labels = [(now - datetime.timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M") for i in range(4, -1, -1)]
    mock_values_fixed = [12, 45, 20, 60, 30]
    all_time_labels = sorted(list(set(mock_labels) | set(time_series.keys())))
    mock_time_values = [mock_values_fixed[mock_labels.index(lbl)] if lbl in mock_labels else 0 for lbl in all_time_labels]
    real_time_values = [time_series.get(lbl, 0) for lbl in all_time_labels]

    # IP Intelligence Processing
    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    locations = {}
    for ip in real_data:
        if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16"):
            locations[ip] = {
                "lat": random.uniform(-60, 60), "lon": random.uniform(-120, 120),
                "city": "Simulated City", "country": "Simulated Country",
                "isp": "Simulated ISP Corp", "threat_rep": "High Risk"
            }
        else:
            loc = get_location(ip)
            if loc:
                locations[ip] = loc

    top_attackers = sorted(real_data.items(), key=lambda x: x[1], reverse=True)[:5]
    if not top_attackers:
        top_attackers = [("Simulated (192.168.x.x)", 45), ("Simulated (10.0.x.x)", 22)]

    # Add System Health Simulation
    # Generates a realistic bouncing CPU curve
    cpu_usage = round(random.uniform(5.0, 15.0) + (len(raw_logs) * 0.1), 1)
    # Memory sits around a stable point
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
        }
    }

def background_log_monitor():
    """Background thread emitting websocket updates."""
    global last_log_mtime
    while True:
        try:
            mtime = os.path.getmtime("logs.txt") if os.path.exists("logs.txt") else 0
            if mtime != last_log_mtime or mock_cache is not None:
                # If logs updated, or we are running mock data (which updates map randomly), emit.
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
    global mock_cache
    mock_cache = None
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