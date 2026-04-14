// Global Chart Defaults
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.scale.grid.color = 'rgba(255, 255, 255, 0.05)';
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15, 23, 42, 0.9)';
Chart.defaults.plugins.tooltip.titleColor = '#f8fafc';
Chart.defaults.plugins.tooltip.padding = 10;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.1)';
Chart.defaults.plugins.tooltip.borderWidth = 1;

// ====== 1. SPA NAVIGATION LOGIC ======
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view-section');

navItems.forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        // Remove active from all
        navItems.forEach(n => n.classList.remove('active'));
        views.forEach(v => {
            v.classList.remove('active');
            v.classList.add('hidden');
        });
        
        // Add active to clicked
        item.classList.add('active');
        const targetId = item.getAttribute('data-target');
        const targetView = document.getElementById(targetId);
        targetView.classList.remove('hidden');
        targetView.classList.add('active');
        
        // Trigger resize on map/charts to fix sizing issues when hidden
        setTimeout(() => {
            if(window.map) window.map.invalidateSize();
            if(window.timelineChart) window.timelineChart.resize();
            if(window.typeChart) window.typeChart.resize();
        }, 100);
    });
});

// ====== 2. CHARTS INITIALIZATION ======
const ctxTime = document.getElementById('timelineChart').getContext('2d');
const gradientArea = ctxTime.createLinearGradient(0, 0, 0, 400);
gradientArea.addColorStop(0, 'rgba(16, 185, 129, 0.5)');
gradientArea.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

window.timelineChart = new Chart(ctxTime, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Simulated Baseline',
                data: [],
                borderColor: '#64748b',
                borderWidth: 2, borderDash: [5, 5],
                tension: 0.4, fill: false,
                pointRadius: 2
            },
            {
                label: 'Live Attack Activity',
                data: [],
                borderColor: '#10b981',
                backgroundColor: gradientArea,
                borderWidth: 2, tension: 0.4, fill: true,
                pointBackgroundColor: '#050510', pointBorderColor: '#10b981',
                pointBorderWidth: 2, pointRadius: 4, pointHoverRadius: 6
            }
        ]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom' },
            zoom: {
                zoom: { wheel: { enabled: true }, pinch: { enabled: true }, mode: 'x' },
                pan: { enabled: true, mode: 'x' }
            }
        },
        scales: { y: { beginAtZero: true }, x: { grid: { display: false } } }
    }
});

const ctxType = document.getElementById('typeChart').getContext('2d');
window.typeChart = new Chart(ctxType, {
    type: 'doughnut',
    data: {
        labels: ['Brute Force', 'Malware', 'Scanning', 'Unknown'],
        datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: ['#ef4444', '#8b5cf6', '#10b981', '#64748b'],
            borderWidth: 0,
            hoverOffset: 10
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'right' } },
        cutout: '70%'
    }
});

// ====== 3. MAP INITIALIZATION ======
window.map = L.map('map', { zoomControl: false }).setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(window.map);
L.control.zoom({ position: 'bottomright' }).addTo(window.map);

let markers = {};
const pulseIcon = L.divIcon({
    className: 'custom-div-icon',
    html: "<div class='pulse-marker' style='width:12px; height:12px;'></div>",
    iconSize: [12, 12], iconAnchor: [6, 6]
});

// ====== 4. SOCKET.IO REAL-TIME LOGIC ======
const socket = io();
let globalLogs = []; // Store logs for search parsing

socket.on('dashboard_update', (d) => {
    // Top Bar Stats
    document.getElementById("kpi-events").innerText = d.rate || 0;
    
    // Calculate Active Threats & Unique
    let highThreats = 0;
    for(let ip in d.suspicious) { if (d.suspicious[ip].severity === 'HIGH') highThreats++; }
    document.getElementById("kpi-threats").innerText = highThreats;
    document.getElementById("kpi-unique").innerText = d.ips ? d.ips.length : 0;
    
    // Alive Connection Count simulation (random jitter based on unique IPs)
    const baseConn = Math.max(1, Math.floor(d.ips.length * 0.3));
    document.getElementById("sys-conn").innerText = baseConn + Math.floor(Math.random()*3);

    // System Health CPU/Mem
    if(d.system_health) {
        document.getElementById("sys-cpu").innerText = `${d.system_health.cpu}%`;
        document.getElementById("sys-mem").innerText = `${d.system_health.mem}%`;
    }

    // Alert Banner
    const alertBox = document.getElementById("alertBox");
    const alertMessage = document.getElementById("alertMessage");
    if (highThreats > 0) {
        alertBox.className = "alert-pill danger";
        alertMessage.innerText = `CRITICAL: ${highThreats} High Severity Threats Active`;
    } else {
        alertBox.className = "alert-pill safe";
        alertMessage.innerText = "System Operating Normally";
    }

    // Timeline Chart Update
    // Do not overwrite completely to preserve zoom state if zoomed in, but standard arrays update is fine
    window.timelineChart.data.labels = d.time_labels;
    window.timelineChart.data.datasets[0].data = d.mock_time_values;
    window.timelineChart.data.datasets[1].data = d.real_time_values;
    window.timelineChart.update('none'); // Update without full animation for smoother real-time

    // Type Chart Update
    if(d.attack_classes) {
        window.typeChart.data.datasets[0].data = [
            d.attack_classes['Brute Force'] || 0,
            d.attack_classes['Malware'] || 0,
            d.attack_classes['Scanning'] || 0,
            d.attack_classes['Unknown'] || 0
        ];
        window.typeChart.update();
    }

    // Top Attackers
    const topList = document.getElementById("top-attackers");
    let topHTML = "";
    if (d.top && d.top.length > 0) {
        d.top.forEach(attacker => {
            topHTML += `
                <div class="attacker-item fade-in">
                    <span class="attacker-ip">${attacker[0]}</span>
                    <span class="attacker-count">${attacker[1]} attempts</span>
                </div>
            `;
        });
    }
    topList.innerHTML = topHTML;

    // Map Update
    for (let key in markers) { window.map.removeLayer(markers[key]); }
    markers = {};
    for (let ip in d.locations) {
        let loc = d.locations[ip];
        if (loc && loc.lat) {
            let m = L.marker([loc.lat, loc.lon], {icon: pulseIcon})
                .addTo(window.map)
                .bindPopup(`<b>${ip}</b><br>${loc.city}, ${loc.country}<br>ISP: <span style="color:#ef4444">${loc.isp || 'Unknown'}</span><br>Rep: ${loc.threat_rep || 'Unknown'}`);
            markers[ip] = m;
        }
    }

    // Update Logs & Threat Intel Views
    if(d.raw_logs) {
        globalLogs = d.raw_logs;
        renderLogs();
    }
    
    if(d.suspicious) {
        renderThreats(d.suspicious, d.locations);
    }
});

// ====== 4.5 REAL-TIME TOASTS & EVENTS ======
socket.on('new_attack', (data) => {
    // Show toast
    showToast(`⚠ New attack from ${data.ip} (${data.type})`, data.type === 'Brute Force' ? 'danger' : 'warn');
    
    // Add ping to map strictly
    if(window.map && d.locations && d.locations[data.ip]) {
        let loc = d.locations[data.ip];
        L.circle([loc.lat, loc.lon], {
            radius: 50000, color: "red", className: "pulse-circle"
        }).addTo(window.map);
    }
});

function showToast(msg, type='warn') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast fade-in ${type}`;
    toast.innerHTML = msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// ====== 5. LOG EXPLORER & THREATS RENDER ======
let sortAscending = false;

function renderLogs() {
    const term = document.getElementById('logSearch').value.toLowerCase();
    const fType = document.getElementById('logFilterType').value;
    const fOrigin = document.getElementById('logFilterOrigin') ? document.getElementById('logFilterOrigin').value : 'All';
    const tBody = document.getElementById('logTableBody');
    tBody.innerHTML = '';
    
    let filtered = globalLogs.filter(log => {
        const matchSearch = log.ip.includes(term) || log.payload.toLowerCase().includes(term);
        const matchType = fType === 'All' || log.type === fType;
        const matchOrigin = fOrigin === 'All' || (fOrigin === 'true' && log.is_real) || (fOrigin === 'false' && !log.is_real);
        return matchSearch && matchType && matchOrigin;
    });

    if (sortAscending) {
        filtered = filtered.reverse();
    }

    filtered.slice(0, 50).forEach(log => {
        tBody.innerHTML += `
            <tr>
                <td>${log.timestamp}</td>
                <td><span style="color:${log.is_real ? '#10b981' : '#ef4444'}">${log.ip}</span></td>
                <td><span class="badge ${log.type.replace(' ','')}">${log.type}</span></td>
                <td>${log.payload.substring(0,40)}${log.payload.length > 40 ? '...':''}</td>
                <td>Port ${log.port}</td>
            </tr>
        `;
    });
}

// Attach filters
if (document.getElementById('sortTime')) {
    document.getElementById('sortTime').addEventListener('click', () => {
        sortAscending = !sortAscending;
        renderLogs();
    });
}
document.getElementById('logSearch').addEventListener('input', renderLogs);
document.getElementById('logFilterType').addEventListener('change', renderLogs);
if (document.getElementById('logFilterOrigin')) document.getElementById('logFilterOrigin').addEventListener('change', renderLogs);

function renderThreats(suspiciousList, locations) {
    const grid = document.getElementById('threatGrid');
    grid.innerHTML = '';
    
    let count = 0;
    for(let ip in suspiciousList) {
        count++;
        let s = suspiciousList[ip];
        let loc = locations[ip] || {};
        let sevClass = s.severity === 'HIGH' ? 'high-sev' : 'med-sev';
        let color = s.severity === 'HIGH' ? 'var(--neon-crimson)' : 'var(--neon-purple)';
        
        grid.innerHTML += `
            <div class="threat-card fade-in ${sevClass}" style="cursor:pointer" onclick="openStoryModal('${ip}', '${color}', '${s.type}')">
                <div class="threat-ip" style="color:${color}">${ip}</div>
                <div class="threat-meta">
                    <span><strong>Severity:</strong> <span style="color:${color}">${s.severity}</span></span>
                    <span><strong>Attack Type:</strong> ${s.type}</span>
                    <span><strong>Attempts:</strong> ${s.count} block events</span>
                    <span><strong>Risk Score:</strong> ${s.score} / 100</span>
                    <span style="color:var(--neon-crimson)"><strong>${s.anomaly ? '⚠ Anomaly Detected' : ''}</strong></span>
                </div>
            </div>
        `;
    }
    if(count === 0) {
        grid.innerHTML = `<div class="subtext">No elevated threats identified.</div>`;
    }
}

// ====== 5.5 ATTACK STORY MODAL ======
function openStoryModal(ip, color, type) {
    document.getElementById('story-modal').classList.remove('hidden');
    document.getElementById('story-ip').innerText = ip;
    document.getElementById('story-ip').style.color = color;
    
    // Compute History
    let history = globalLogs.filter(l => l.ip === ip);
    let counts = { 'Brute Force':0, 'Scanning':0, 'Malware':0 };
    history.forEach(h => { if(h.type in counts) counts[h.type]++; });
    
    document.getElementById('story-meta').innerHTML = `
        Identified as <strong>${type}</strong> threat actor. <br>
        Breakdown: ${counts['Brute Force']} Brute Force attempts, ${counts['Scanning']} Scans.
    `;
    
    let tHtml = "";
    history.slice(0, 10).forEach(h => {
        tHtml += `<div><span class="badge ${h.type.replace(' ','')}">${h.type}</span> ${h.timestamp} - Port ${h.port}</div>`;
    });
    document.getElementById('story-timeline').innerHTML = tHtml;
}

document.getElementById('close-story').addEventListener('click', () => {
    document.getElementById('story-modal').classList.add('hidden');
});

// ====== 6. SETTINGS AUTH & SECURITY ======
async function unlockSettings() {
    const pw = document.getElementById("adminPassword").value;
    const err = document.getElementById("loginError");
    
    try {
        const res = await fetch("/api/auth", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({password: pw})
        });
        
        if(res.ok) {
            document.querySelector('.locked-card').classList.add('hidden');
            document.getElementById('settingsPanel').classList.remove('hidden');
        } else if (res.status === 429) {
            err.innerText = "Too many attempts. Rate limited.";
            err.classList.remove('hidden');
        } else {
            err.innerText = "Invalid credentials";
            err.classList.remove('hidden');
        }
    } catch(e) {
        err.innerText = "Connection error";
        err.classList.remove('hidden');
    }
}

document.getElementById('configSaveBtn').addEventListener('click', async () => {
    const port = document.getElementById('configPort').value;
    await fetch("/update-config", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ port: port })
    });
    showToast("Configuration saved. Restart server.py to apply.", "warn");
});

document.getElementById('configPurgeBtn').addEventListener('click', async () => {
    await fetch("/api/purge", { method: "POST" });
    showToast("All logs purged successfully.", "warn");
});

// Uptime visual counter
let fakeMinutes = 12;
setInterval(() => {
    fakeMinutes++;
    document.getElementById("sys-uptime").innerText = `24h ${fakeMinutes}m`;
}, 60000);
