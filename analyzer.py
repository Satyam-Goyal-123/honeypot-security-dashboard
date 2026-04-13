from collections import Counter, defaultdict, deque

def analyze_logs(max_lines=5000):
    real_ips = []
    fake_ips = []
    time_series = defaultdict(int)

    try:
        with open("logs.txt", "r", encoding="utf-8", errors="ignore") as f:
            # We use a deque to keep only the last `max_lines` from the log
            recent_lines = deque(f, max_lines)
            
            for line in recent_lines:
                parts = line.strip().split("|")
                if len(parts) < 3:
                    continue

                try:
                    timestamp = parts[0].strip()
                    ip_port = parts[1].strip()
                    ip = ip_port.split(":")[0].strip() if ":" in ip_port else ip_port
                    data = "|".join(parts[2:]) # Rejoin in case data had a pipe

                    # take e.g. "2023-10-24 14:30" (first 16 chars of standard datetime)
                    time_key = timestamp[:16]
                    if len(time_key) == 16:
                        time_series[time_key] += 1

                    if "[REAL]" in data:
                        real_ips.append(ip)
                    elif "[FAKE]" in data:
                        fake_ips.append(ip)
                except Exception as parse_err:
                    print(f"Skipping malformed line: {line} - Error: {parse_err}")
                    continue

    except FileNotFoundError:
        pass

    real_count = Counter(real_ips)
    fake_count = Counter(fake_ips)

    suspicious = [ip for ip, c in real_count.items() if c >= 3]

    return dict(real_count), dict(fake_count), suspicious, dict(time_series)