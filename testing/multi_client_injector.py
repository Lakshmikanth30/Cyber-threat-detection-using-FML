"""
Multi-client Dashboard Injector
--------------------------------
Spawn multiple simulated clients that register with the server and send
attack events concurrently. Useful for load-testing the dashboard and
validating multi-client behavior.

Usage (from repo root):
    .\myvenv\Scripts\Activate.ps1
    python testing\multi_client_injector.py --clients 10 --attacks 20 --delay 0.5

"""
import argparse
import threading
import time
import random
from datetime import datetime
import socketio

# Shared attack types and fake IPs (reused from single-client injector)
ATTACK_TYPES = ['BruteForce', 'DoS/DDoS', 'PortScan']
FAKE_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102',
    '10.0.0.50', '10.0.0.51', '10.0.0.52',
    '172.16.0.100', '172.16.0.101', '172.16.0.102'
]


def run_client(client_idx: int, server_url: str, num_attacks: int, delay: float):
    client_id = f"sim_client_{client_idx}"
    sio = socketio.Client()

    connected = threading.Event()

    @sio.event
    def connect():
        connected.set()

    @sio.event
    def disconnect():
        connected.clear()

    try:
        sio.connect(server_url, wait=True, wait_timeout=10)
    except Exception as e:
        print(f"[client {client_id}] Connection failed: {e}")
        return

    if not connected.is_set():
        print(f"[client {client_id}] Could not establish connection")
        return

    # Register
    sio.emit('register_client', {
        'client_id': client_id,
        'client_ip': random.choice(FAKE_IPS)
    })

    blocked = set()

    for i in range(num_attacks):
        attack_type = random.choice(ATTACK_TYPES)
        ip_address = random.choice(FAKE_IPS)
        confidence = random.uniform(0.75, 0.99)
        threat_score = random.randint(1, 3)

        attack_data = {
            'client_id': client_id,
            'ip_address': ip_address,
            'attack_type': attack_type,
            'confidence': confidence,
            'threat_score': threat_score
        }

        try:
            sio.emit('attack_detected', attack_data)
        except Exception as e:
            print(f"[client {client_id}] emit failed: {e}")

        if threat_score >= 2 and ip_address not in blocked and random.random() > 0.4:
            try:
                sio.emit('block_ip', {
                    'client_id': client_id,
                    'ip_address': ip_address,
                    'reason': attack_type
                })
                blocked.add(ip_address)
            except Exception:
                pass

        time.sleep(delay)

    # Send final stats
    try:
        sio.emit('stats_update', {
            'client_id': client_id,
            'stats': {
                'packets_captured': num_attacks * 120,
                'packets_processed': int(num_attacks * 110),
                'attacks_detected': num_attacks,
                'ips_blocked': len(blocked)
            }
        })
    except Exception:
        pass

    # Keep connection for a short while so server updates are visible
    time.sleep(2.0)
    try:
        sio.disconnect()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description='Spawn multiple simulated NIDS clients')
    parser.add_argument('--server', default='http://127.0.0.1:5001', help='Server URL')
    parser.add_argument('--clients', type=int, default=5, help='Number of clients to spawn')
    parser.add_argument('--attacks', type=int, default=20, help='Attacks per client')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attacks (s)')

    args = parser.parse_args()

    threads = []
    print(f"Starting {args.clients} clients -> {args.server} (each {args.attacks} attacks, {args.delay}s delay)")

    for i in range(args.clients):
        t = threading.Thread(target=run_client, args=(i + 1, args.server, args.attacks, args.delay), daemon=True)
        threads.append(t)
        t.start()
        time.sleep(0.1)

    for t in threads:
        t.join()

    print("All clients finished.")


if __name__ == '__main__':
    main()
