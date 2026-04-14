from collections import Counter, defaultdict, deque

def get_attack_type(data):
    """Classifies attack based on payload signature."""
    lower_data = data.lower()
    if "admin" in lower_data or "root" in lower_data or "password" in lower_data:
        return "Brute Force"
    elif "wget" in lower_data or "curl" in lower_data or ".sh" in lower_data:
        return "Malware"
    elif "nmap" in lower_data or "scan" in lower_data:
        return "Scanning"
    else:
        return "Unknown"

def analyze_logs(max_lines=5000):
    real_ips = []
    fake_ips = []
    time_series = defaultdict(int)
    real_time_series = defaultdict(int)
    attack_classes = defaultdict(int)
    real_attack_classes = defaultdict(int)
    raw_logs = []
    
    # Store the last attack type per IP to enrich the suspicious list
    last_attack_type = {}

    try:
        with open("logs.txt", "r", encoding="utf-8", errors="ignore") as f:
            # We use a deque to keep only the last `max_lines` from the log
            recent_lines = deque(f, max_lines)
            
            for line in recent_lines:
                parts = line.strip().split("|")
                if len(parts) < 3:
                    continue

                try:
                    # Since we updated the logger, parts might be length 4
                    if len(parts) >= 4:
                        timestamp = parts[0].strip()
                        ip_port = parts[1].strip()
                        a_type = parts[2].strip()
                        data = "|".join(parts[3:]) 
                    else:
                        timestamp = parts[0].strip()
                        ip_port = parts[1].strip()
                        a_type = get_attack_type("|".join(parts[2:]))
                        data = "|".join(parts[2:]) 
                    
                    ip = ip_port.split(":")[0].strip() if ":" in ip_port else ip_port

                    # take e.g. "2023-10-24 14:30" (first 16 chars of standard datetime)
                    time_key = timestamp[:16]
                    if len(time_key) == 16:
                        time_series[time_key] += 1

                    attack_classes[a_type] += 1
                    
                    # Log object for the Explorer
                    is_real = "[REAL]" in data
                    log_obj = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "port": ip_port.split(":")[1] if ":" in ip_port else "Unknown",
                        "type": a_type,
                        "payload": data[:100], # truncate payload for UI
                        "is_real": is_real
                    }
                    raw_logs.append(log_obj)

                    if is_real:
                        real_ips.append(ip)
                        real_time_series[time_key] += 1
                        real_attack_classes[a_type] += 1
                        last_attack_type[ip] = a_type
                    elif "[FAKE]" in data:
                        fake_ips.append(ip)
                        last_attack_type[ip] = a_type
                        
                except Exception as parse_err:
                    print(f"Skipping malformed line: {line} - Error: {parse_err}")
                    continue

    except FileNotFoundError:
        pass

    real_count = Counter(real_ips)
    fake_count = Counter(fake_ips)

    # Baseline AI Detection (avg * 2)
    avg_attempts = 0
    if real_count:
        avg_attempts = sum(real_count.values()) / len(real_count.values())

    # Dynamic Threat Engine
    suspicious = {}
    for ip, count in real_count.items():
        if count >= 3:
            # Threat Scoring Matrix
            a_type = last_attack_type.get(ip, "Unknown")
            weight = 2 if a_type == "Brute Force" else (3 if a_type == "Malware" else 1.5)
            score = int(count * weight)
            
            severity = "HIGH" if count > 5 else "MEDIUM"
            if count > 10:
                severity = "CRITICAL"
                
            anomaly = count > (avg_attempts * 2)

            suspicious[ip] = {
                "count": count,
                "severity": severity,
                "type": a_type,
                "score": score,
                "anomaly": anomaly
            }

    return {
        "real_count": dict(real_count),
        "fake_count": dict(fake_count),
        "suspicious": suspicious,
        "time_series": dict(time_series),
        "real_time_series": dict(real_time_series),
        "attack_classes": dict(attack_classes),
        "real_attack_classes": dict(real_attack_classes),
        "raw_logs": list(reversed(raw_logs)) # return newest first
    }