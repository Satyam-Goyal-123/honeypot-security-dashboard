from flask import Flask, jsonify
from analyzer import analyze_logs
from geo import get_location

app = Flask(__name__)

# 🔥 API for live updates
@app.route("/data")
def data():
    real_data, fake_data, suspicious, time_series = analyze_logs()

    all_ips = list(set(real_data.keys()) | set(fake_data.keys()))
    real_values = [real_data.get(ip, 0) for ip in all_ips]
    fake_values = [fake_data.get(ip, 0) for ip in all_ips]

    locations = {}
    for ip in real_data:
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
    return """
<html>
<head>
<title>SOC Dashboard</title>

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>

/* 🌌 Animated Background */
body {
    margin: 0;
    font-family: 'Inter', sans-serif;
    color: #e5e7eb;
    background: linear-gradient(-45deg, #020617, #020617, #020617, #0f172a);
    background-size: 400% 400%;
    animation: gradientMove 15s ease infinite;
}

@keyframes gradientMove {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

/* Title */
h1 {
    text-align: center;
    font-size: 22px;
    margin: 30px 0;
    font-weight: 600;
    letter-spacing: 0.5px;
}

/* Layout */
.container {
    max-width: 1100px;
    margin: auto;
    padding: 20px;
}

/* Grid */
.grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
}

/* 🧊 Glass Cards */
.card {
    background: rgba(17, 24, 39, 0.6);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 14px;
    padding: 20px;
    transition: all 0.3s ease;
}

/* Hover */
.card:hover {
    transform: translateY(-4px);
    border-color: rgba(255,255,255,0.1);
}

/* Headings */
.card h3 {
    font-size: 13px;
    color: #9ca3af;
    margin-bottom: 12px;
    font-weight: 500;
}

/* Values */
.value {
    font-size: 20px;
    font-weight: 600;
}

/* Alert */
.alert {
    text-align: center;
    padding: 12px;
    font-size: 13px;
    margin-bottom: 15px;
    transition: all 0.3s ease;
}

/* Charts */
canvas {
    max-height: 250px;
}

/* Map */
#map {
    height: 300px;
    border-radius: 12px;
    overflow: hidden;
}

/* Subtext */
.small {
    font-size: 13px;
    color: #9ca3af;
}

/* Fade-in animation */
.fade {
    animation: fadeIn 0.6s ease forwards;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Responsive */
@media (max-width: 768px) {
    .grid {
        grid-template-columns: 1fr;
    }
}

</style>
</head>

<body>

<h1 class="fade">Honeypot Security Dashboard</h1>

<div id="alertBox" class="alert fade"></div>

<div class="container">

    <div class="grid">
        <div class="card fade">
            <h3>Top Attackers</h3>
            <div id="top" class="value"></div>
        </div>

        <div class="card fade">
            <h3>Attack Rate</h3>
            <div id="rate" class="value"></div>
        </div>
    </div>

    <div class="grid">
        <div class="card fade">
            <h3>Attack Distribution</h3>
            <canvas id="chart"></canvas>
        </div>

        <div class="card fade">
            <h3>Activity Timeline</h3>
            <canvas id="timeChart"></canvas>
        </div>
    </div>

    <div class="card fade">
        <h3>Geolocation Map</h3>
        <div id="map"></div>
    </div>

</div>

<script>

let chart = new Chart(document.getElementById("chart"), {
    type:'bar',
    data:{labels:[],datasets:[
        {label:'Real',data:[],backgroundColor:'#f87171'},
        {label:'Fake',data:[],backgroundColor:'#60a5fa'}
    ]}
});

let timeChart = new Chart(document.getElementById("timeChart"), {
    type:'line',
    data:{labels:[],datasets:[
        {label:'Activity',data:[],borderColor:'#34d399'}
    ]}
});

let map = L.map('map').setView([20,0],2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

async function update(){
    const res = await fetch("/data");
    const d = await res.json();

    chart.data.labels = d.ips;
    chart.data.datasets[0].data = d.real;
    chart.data.datasets[1].data = d.fake;
    chart.update();

    timeChart.data.labels = d.time_labels;
    timeChart.data.datasets[0].data = d.time_values;
    timeChart.update();

    let alert = document.getElementById("alertBox");
    if(d.suspicious.length){
        alert.innerHTML = "⚠ Active Threat Detected";
        alert.style.color = "#f87171";
    } else {
        alert.innerHTML = "System Operating Normally";
        alert.style.color = "#34d399";
    }

    let topHTML = "";
    d.top.forEach(x=>{
        topHTML += `<div class="small">${x[0]} — ${x[1]} attempts</div>`;
    });
    document.getElementById("top").innerHTML = topHTML;

    document.getElementById("rate").innerHTML = d.rate + " events";

    map.eachLayer(l=>{
        if(l instanceof L.Marker) map.removeLayer(l);
    });

    for(let ip in d.locations){
        let loc = d.locations[ip];
        L.marker([loc.lat,loc.lon]).addTo(map).bindPopup(ip);
    }
}

setInterval(update,2000);
update();

</script>

</body>
</html>
"""


if __name__ == "__main__":
    app.run(debug=True, port=5001)