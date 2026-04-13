from collections import Counter

def analyze_logs():
    real_ips = []
    fake_ips = []

    try:
        with open("logs.txt") as f:
            for line in f:
                parts = line.strip().split("|")

                if len(parts) < 3:
                    continue

                ip = parts[1].strip().split(":")[0]

                # 🔥 CLEAN DATA PROPERLY
                data = parts[2].strip()

                if "[FAKE]" in data:
                    fake_ips.append(ip)
                elif "[REAL]" in data:
                    real_ips.append(ip)

    except FileNotFoundError:
        return {}, {}

    return dict(Counter(real_ips)), dict(Counter(fake_ips))