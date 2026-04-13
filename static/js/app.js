// Chart global defaults for dark mode aesthetics
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.scale.grid.color = 'rgba(255, 255, 255, 0.05)';
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15, 23, 42, 0.9)';
Chart.defaults.plugins.tooltip.titleColor = '#f8fafc';
Chart.defaults.plugins.tooltip.padding = 10;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.1)';
Chart.defaults.plugins.tooltip.borderWidth = 1;

// Initialize Bar Chart (Target Distribution)
const ctxDist = document.getElementById('distributionChart').getContext('2d');
const distributionChart = new Chart(ctxDist, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Real Service Hits',
                data: [],
                backgroundColor: '#ef4444',
                borderRadius: 4,
                barPercentage: 0.6
            },
            {
                label: 'Fake Service Hits',
                data: [],
                backgroundColor: '#06b6d4',
                borderRadius: 4,
                barPercentage: 0.6
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom' }
        },
        scales: {
            y: { beginAtZero: true }
        }
    }
});

// Initialize Line Chart (Activity Timeline)
const ctxTime = document.getElementById('timelineChart').getContext('2d');

// Gradient for line chart
const gradientArea = ctxTime.createLinearGradient(0, 0, 0, 400);
gradientArea.addColorStop(0, 'rgba(16, 185, 129, 0.5)');
gradientArea.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

const timelineChart = new Chart(ctxTime, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Simulated Benchmark',
                data: [],
                borderColor: '#64748b', // Slate color for mock data
                borderWidth: 2,
                borderDash: [5, 5], // Dashed line to indicate simulated
                tension: 0.4,
                fill: false,
                pointBackgroundColor: '#050510',
                pointBorderColor: '#64748b',
                pointBorderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5
            },
            {
                label: 'Live Attacks',
                data: [],
                borderColor: '#10b981', // Neon green for real data
                backgroundColor: gradientArea,
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#050510',
                pointBorderColor: '#10b981',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false }
        },
        scales: {
            y: { beginAtZero: true },
            x: {
                grid: { display: false }
            }
        }
    }
});

// Initialize Leaflet Map
const map = L.map('map', {
    zoomControl: false // clean minimal look
}).setView([20, 0], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: 'Map data © <a href="https://openstreetmap.org">OpenStreetMap</a>'
}).addTo(map);

// Add zoom control manually to bottom right
L.control.zoom({ position: 'bottomright' }).addTo(map);

// Keep track of markers to efficiently update
let markers = {};

// Custom dot icon for map
const threatIcon = L.divIcon({
    className: 'custom-div-icon',
    html: "<div style='background-color:#ef4444; width:12px; height:12px; border-radius:50%; border:2px solid #050510; box-shadow: 0 0 10px #ef4444;'></div>",
    iconSize: [12, 12],
    iconAnchor: [6, 6]
});

// Update Function
async function updateDashboard() {
    try {
        const res = await fetch("/data");
        const d = await res.json();

        // 1. Update Distribution Chart
        distributionChart.data.labels = d.ips;
        distributionChart.data.datasets[0].data = d.real;
        distributionChart.data.datasets[1].data = d.fake;
        distributionChart.update();

        // 2. Update Timeline Chart
        timelineChart.data.labels = d.time_labels;
        timelineChart.data.datasets[0].data = d.mock_time_values; // Simulated baseline
        timelineChart.data.datasets[1].data = d.real_time_values; // Live data
        timelineChart.update();

        // 3. Update Threat Level Alert
        const alertBox = document.getElementById("alertBox");
        const alertMessage = document.getElementById("alertMessage");
        const threatLvlText = document.getElementById("threat-level");
        
        alertBox.classList.remove("hidden");

        if (d.suspicious && d.suspicious.length > 0) {
            alertBox.classList.remove("safe");
            alertMessage.innerText = `⚠ ACTIVE THREAT DETECTED: ${d.suspicious.length} suspicious IPs flagged.`;
            threatLvlText.innerText = "HIGH";
            threatLvlText.className = "value-large threat-level high";
        } else {
            alertBox.classList.add("safe");
            alertMessage.innerText = "System Operating Normally - No immediate threats.";
            threatLvlText.innerText = "LOW";
            threatLvlText.className = "value-large threat-level";
        }

        // 4. Update Top Attackers
        const topList = document.getElementById("top-attackers");
        let topHTML = "";
        if (d.top && d.top.length > 0) {
            d.top.forEach(attacker => {
                topHTML += `
                    <div class="attacker-item">
                        <span class="attacker-ip">${attacker[0]}</span>
                        <span class="attacker-count">${attacker[1]} attempts</span>
                    </div>
                `;
            });
        } else {
            topHTML = `<div class="subtext">No attacker data available</div>`;
        }
        topList.innerHTML = topHTML;

        // 5. Update Total Events
        document.getElementById("rate").innerText = d.rate || 0;

        // 6. Update Map Markers
        // Clear all markers first (inefficient but safe. To optimize, only delta)
        for (let key in markers) {
             map.removeLayer(markers[key]);
        }
        markers = {};

        for (let ip in d.locations) {
            let loc = d.locations[ip];
            if (loc && loc.lat !== undefined && loc.lon !== undefined) {
                let marker = L.marker([loc.lat, loc.lon], {icon: threatIcon})
                    .addTo(map)
                    .bindPopup(`<b>${ip}</b><br>${loc.city || 'Unknown'}, ${loc.country || 'Unknown'}`);
                markers[ip] = marker;
            }
        }
    } catch (err) {
        console.error("Dashboard Update Error:", err);
    }
}

// Initial fetch and start interval
updateDashboard();
setInterval(updateDashboard, 2000);
