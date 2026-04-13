import socket
import random
from logger import log_attack

HOST = "0.0.0.0"
PORT = 9999

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

    try:
        client.sendall(b"Fake SSH Service\nUsername: ")

        data = client.recv(1024).strip()   # 🔥 FIX HERE

        print(f"[DATA] {data}")

        log_attack(ip, port, data + tag + b"\n")  # 🔥 FIX HERE

        client.sendall(b"Login Failed\n")

    except Exception as e:
        print("Error:", e)

    client.close()