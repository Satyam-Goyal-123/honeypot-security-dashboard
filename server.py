import socket
import random
import json
import os
from logger import log_attack

HOST = "0.0.0.0"
PORT = 9999

if os.path.exists("config.json"):
    try:
        with open("config.json", "r") as f:
            cfg = json.load(f)
            if "port" in cfg:
                PORT = int(cfg["port"])
    except:
        pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print(f"[+] Honeypot running on port {PORT}...")

fake_ips = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.3",
    "203.0.113.1",
    "45.33.32.156"
]

import requests

def classify_attack(data_bytes):
    d = data_bytes.decode(errors="ignore").lower()
    if "admin" in d or "password" in d or "root" in d:
        return "Brute Force"
    elif "wget" in d or "curl" in d:
        return "Malware"
    elif "scan" in d or "nmap" in d:
        return "Scanning"
    else:
        return "Unknown"

while True:
    client, addr = server.accept()

    real_ip = addr[0]
    port = addr[1]

    if real_ip == "127.0.0.1":
        ip = random.choice(fake_ips)
        tag = b" [FAKE]"
    else:
        ip = real_ip
        tag = b" [REAL]"

    print(f"[!] Connection from {ip}:{port}")
    client.settimeout(5.0)

    try:
        client.sendall(b"Fake SSH Service\nUsername: ")
        raw_data = client.recv(1024).strip()
        
        data_str = raw_data.decode(errors='ignore') if raw_data else "<empty>"
        print(f"[DATA] {data_str}")

        # tag is bytes, so we encode our strings to form the final byte string
        log_payload = raw_data + tag + b"\n" if raw_data else b"<empty>" + tag + b"\n"
        
        # Classification
        a_type = classify_attack(log_payload)
        
        # Log it locally
        log_attack(ip, port, log_payload, a_type)

        # Emit instant real-time payload to UI Dashboard process
        try:
            requests.post("http://127.0.0.1:5001/api/internal/event", json={
                "ip": ip,
                "port": port,
                "type": a_type,
                "payload": data_str
            }, timeout=1.0)
        except Exception:
            pass # App might not be running

        client.sendall(b"Login Failed\n")

    except socket.timeout:
        print(f"[-] Connection timed out for {ip}")
    except Exception as e:
        print(f"[-] Error with {ip}:", e)
    finally:
        client.close()