from flask import Flask
from analyzer import analyze_logs
from geo import get_location

app = Flask(__name__)

@app.route("/")
def home():
    real_data, fake_data, suspicious, time_series = analyze_logs()

    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    # 🌍 GEO LOCATIONS
    locations = {}
    for ip in real_data.keys():
        loc = get_location(ip)
        if loc:
            locations[ip] = loc

    # 📈 TIME DATA
    time_labels = list(time_series.keys())
    time_values = list(time_series.values())

    html = f"""
    <html>
    <head>
        <title>Honeypot SOC Dashboard</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">

        <!-- Chart.js -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <!-- Leaflet -->
        <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
        <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

        <style>
            body {{
                margin: 0;
                font-family: 'Inter', sans-serif;
                background: #020617;
                color: #e2e8f0;
            }}

            h1 {{
                text-align: center;
                margin: 30px 0;
                font-weight: 600;
            }}

            .container {{
                max-width: 1200px;
                margin: auto;
                padding: 20px;
            }}

            .grid-2 {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-bottom: 20px;
            }}

            .grid-1 {{
                margin-bottom: 20px;
            }}

            .card {{
                background: #0f172a;
                padding: 20px;
                border-radius: 12px;
                border: 1px solid #1e293b;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            }}

            .card h3 {{
                margin-bottom: 15px;
                font-weight: 500;
            }}

            .danger {{
                color: #ef4444;
                font-weight: bold;
            }}

            canvas {{
                max-height: 300px;
            }}

            #map {{
                height: 350px;
                border-radius: 10px;
                overflow: hidden;
            }}

            @media (max-width: 768px) {{
                .grid-2 {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>

    <body>

        <h1>🛡️ Honeypot SOC Dashboard</h1>

        <div class="container">

            <!-- Row 1 -->
            <div class="grid-2">
                <div class="card">
                    <h3>🔴 Real Attackers</h3>
                    {"".join(f"<div>{ip} → {count}</div>" for ip,count in real_data.items())}
                </div>

                <div class="card">
                    <h3>🔵 Simulated Attackers</h3>
                    {"".join(f"<div>{ip} → {count}</div>" for ip,count in fake_data.items())}
                </div>
            </div>

            <!-- Row 2 -->
            <div class="grid-1">
                <div class="card">
                    <h3>⚠ Suspicious Activity</h3>
                    { "".join(f"<div class='danger'>⚠ {ip} (Brute Force)</div>" for ip in suspicious) if suspicious else "<div>No threats detected</div>" }
                </div>
            </div>

            <!-- Row 3 -->
            <div class="grid-2">
                <div class="card">
                    <h3>📊 Attack Chart</h3>
                    <canvas id="chart"></canvas>
                </div>

                <div class="card">
                    <h3>📈 Time Activity</h3>
                    <canvas id="timeChart"></canvas>
                </div>
            </div>

            <!-- Row 4 -->
            <div class="grid-1">
                <div class="card">
                    <h3>🌍 Attacker Map</h3>
                    <div id="map"></div>
                </div>
            </div>

        </div>

        <script>
            const labels = {all_ips};
            const real_values = {real_values};
            const fake_values = {fake_values};

            new Chart(document.getElementById('chart'), {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [
                        {{
                            label: 'Real Attacks',
                            data: real_values,
                            backgroundColor: '#ef4444'
                        }},
                        {{
                            label: 'Simulated Attacks',
                            data: fake_values,
                            backgroundColor: '#3b82f6'
                        }}
                    ]
                }}
            }});

            // TIME GRAPH
            new Chart(document.getElementById('timeChart'), {{
                type: 'line',
                data: {{
                    labels: {time_labels},
                    datasets: [{{
                        label: 'Attacks over Time',
                        data: {time_values},
                        borderColor: '#22c55e',
                        fill: false
                    }}]
                }}
            }});

            // MAP
            const map = L.map('map').setView([20, 0], 2);

            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);

            const locations = {locations};

            for (let ip in locations) {{
                let loc = locations[ip];
                L.marker([loc.lat, loc.lon])
                    .addTo(map)
                    .bindPopup(ip + " - " + loc.city + ", " + loc.country);
            }}
        </script>

    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(debug=True, port=5001)