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
                ip = parts[1].split(":")[0].strip()
                data = parts[2]

                time_key = timestamp[:16]
                time_series[time_key] += 1

                if "[REAL]" in data:
                    real_ips.append(ip)
                elif "[FAKE]" in data:
                    fake_ips.append(ip)

    except FileNotFoundError:
        return {}, {}, [], {}

    real_count = Counter(real_ips)
    fake_count = Counter(fake_ips)

    suspicious = [ip for ip, c in real_count.items() if c >= 3]

    return dict(real_count), dict(fake_count), suspicious, dict(time_series)