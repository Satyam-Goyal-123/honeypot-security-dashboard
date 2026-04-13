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

    # Set a timeout so we don't stall on idle malicious connections
    client.settimeout(5.0)

    try:
        client.sendall(b"Fake SSH Service\nUsername: ")

        # Safely read data with a timeout
        raw_data = client.recv(1024).strip()
        
        # Safely decode ignoring bad bytes
        data_str = raw_data.decode(errors='ignore') if raw_data else "<empty>"
        
        print(f"[DATA] {data_str}")

        # tag is bytes, so we encode our strings to form the final byte string
        log_payload = raw_data + tag + b"\n" if raw_data else b"<empty>" + tag + b"\n"
        log_attack(ip, port, log_payload)

        client.sendall(b"Login Failed\n")

    except socket.timeout:
        print(f"[-] Connection timed out for {ip}")
    except Exception as e:
        print(f"[-] Error with {ip}:", e)
    finally:
        client.close()