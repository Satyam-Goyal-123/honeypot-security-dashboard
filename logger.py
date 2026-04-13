import datetime

def log_attack(ip, port, data):
    with open("logs.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} | {ip}:{port} | {data.decode(errors='ignore')}\n")