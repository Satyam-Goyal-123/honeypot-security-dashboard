import datetime

import datetime

def log_attack(ip, port, data, attack_type="Unknown"):
    with open("logs.txt", "a", encoding="utf-8") as f:
        # data is expected to be bytes since its being decoded
        if isinstance(data, bytes):
            payload_str = data.decode(errors='ignore').replace('\n', ' ')
        else:
            payload_str = str(data).replace('\n', ' ')
        f.write(f"{datetime.datetime.now()} | {ip}:{port} | {attack_type} | {payload_str}\n")