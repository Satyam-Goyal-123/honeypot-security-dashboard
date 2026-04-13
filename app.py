from flask import Flask
from analyzer import analyze_logs

app = Flask(__name__)

@app.route("/")
def home():
    real_data, fake_data = analyze_logs()

    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))

    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    total_attacks = sum(real_values) + sum(fake_values)
    total_real = sum(real_values)
    total_fake = sum(fake_values)

    alert = "🚨 LIVE ATTACK DETECTED!" if total_real > 0 else "System Monitoring..."

    html = f"""
    <html>
    <head>
        <title>Honeypot SOC Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body {{
                margin: 0;
                font-family: 'Segoe UI', sans-serif;
                background: #020617;
                color: #e2e8f0;
            }}

            h1 {{
                text-align: center;
                margin: 15px;
                color: #38bdf8;
            }}

            .alert {{
                text-align: center;
                padding: 10px;
                background: {'#ef4444' if total_real > 0 else '#1e293b'};
                font-weight: bold;
                letter-spacing: 1px;
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                width: 90%;
                margin: 20px auto;
            }}

            .card {{
                background: #0f172a;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0 0 15px rgba(0,0,0,0.7);
            }}

            .stat {{
                font-size: 28px;
                font-weight: bold;
            }}

            .real {{ color: #ef4444; }}
            .fake {{ color: #3b82f6; }}
            .total {{ color: #22c55e; }}

            .feed {{
                max-height: 200px;
                overflow-y: auto;
            }}

            .feed div {{
                padding: 6px;
                margin: 4px 0;
                background: #1e293b;
                border-left: 4px solid #38bdf8;
            }}

            canvas {{
                margin-top: 20px;
            }}
        </style>
    </head>

    <body>

        <h1>Honeypot SOC Dashboard</h1>

        <div class="alert">{alert}</div>

        <div class="grid">
            <div class="card">
                <h3>Total Attacks</h3>
                <div class="stat total">{total_attacks}</div>
            </div>

            <div class="card">
                <h3>Real Attacks</h3>
                <div class="stat real">{total_real}</div>
            </div>

            <div class="card">
                <h3>Simulated Attacks</h3>
                <div class="stat fake">{total_fake}</div>
            </div>
        </div>

        <div class="grid">

            <div class="card">
                <h3>🔴 Real Attack Feed</h3>
                <div class="feed">
    """

    for ip, count in real_data.items():
        html += f"<div>⚠ {ip} → {count} attempts</div>"

    html += """
                </div>
            </div>
    """

    html += """
            <div class="card">
                <h3>🔵 Simulated Attack Feed</h3>
                <div class="feed">
    """

    for ip, count in fake_data.items():
        html += f"<div>{ip} → {count}</div>"

    html += """
                </div>
            </div>

        </div>
    """

    html += f"""
        <div class="grid">
            <div class="card">
                <h3>📊 Attack Analytics</h3>
                <canvas id="chart"></canvas>
            </div>
        </div>

        <script>
            const labels = {all_ips};
            const real_values = {real_values};
            const fake_values = {fake_values};

            const ctx = document.getElementById('chart').getContext('2d');

            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [
                        {{
                            label: 'Real Attacks',
                            data: real_values,
                            backgroundColor: 'rgba(239,68,68,0.8)'
                        }},
                        {{
                            label: 'Simulated Attacks',
                            data: fake_values,
                            backgroundColor: 'rgba(59,130,246,0.8)'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            labels: {{ color: '#e2e8f0' }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            ticks: {{ color: '#e2e8f0' }}
                        }},
                        y: {{
                            beginAtZero: true,
                            ticks: {{ color: '#e2e8f0' }}
                        }}
                    }}
                }}
            }});

            // 🔥 AUTO REFRESH EVERY 3 SECONDS
            setTimeout(() => location.reload(), 30000);
        </script>

    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(debug=True, port=5001)