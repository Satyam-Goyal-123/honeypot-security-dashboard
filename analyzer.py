from collections import Counter, defaultdict

def analyze_logs():
    real_ips = []
    fake_ips = []
    time_series = defaultdict(int)

    try:
        with open("logs.txt") as f:
            for line in f:
                parts = line.strip().split("|")

                if len(parts) < 3:
                    continue

                timestamp = parts[0].strip()
                ip = parts[1].strip().split(":")[0]
                data = parts[2].strip()

                # 📈 TIME GRAPH (per minute)
                time_key = timestamp[:16]
                time_series[time_key] += 1

                if "[FAKE]" in data:
                    fake_ips.append(ip)
                elif "[REAL]" in data:
                    real_ips.append(ip)

    except FileNotFoundError:
        return {}, {}, [], {}

    real_count = Counter(real_ips)
    fake_count = Counter(fake_ips)

    # 🔐 suspicious detection
    suspicious = [ip for ip, count in real_count.items() if count >= 3]

    return dict(real_count), dict(fake_count), suspicious, dict(time_series)