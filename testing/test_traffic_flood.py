"""
TRAFFIC FLOOD SIMULATOR
=======================
Generates high-volume network traffic to trigger rate-based detection.
This is SAFE - only targets localhost.

Run this while your NIDS client is running to trigger DoS/DDoS or flood detection.
"""

import socket
import threading
import time
import random
import sys

def connection_flood(target, port, count, thread_id):
    """
    Generate rapid connections to simulate flood attack
    
    Args:
        target: Target IP
        port: Target port
        count: Number of connections to make
        thread_id: Thread identifier for logging
    """
    successful = 0
    failed = 0
    
    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            sock.close()
            successful += 1
        except:
            failed += 1
    
    return successful, failed


def udp_flood(target, port, count, packet_size=1024):
    """
    Generate UDP flood
    
    Args:
        target: Target IP
        port: Target port
        count: Number of packets
        packet_size: Size of each packet
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * packet_size
    
    sent = 0
    for i in range(count):
        try:
            sock.sendto(payload, (target, port))
            sent += 1
        except:
            pass
    
    sock.close()
    return sent


def traffic_flood_test(target="127.0.0.1", port=80, mode="tcp", intensity="medium"):
    """
    Main flood test function
    
    Args:
        target: IP to target (default: localhost - SAFE)
        port: Port to target
        mode: 'tcp' or 'udp'
        intensity: 'low', 'medium', 'high'
    """
    print("=" * 70)
    print("🌊 TRAFFIC FLOOD ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Target: {target}:{port} (SAFE - targeting yourself)")
    print(f"Mode: {mode.upper()}")
    print(f"Intensity: {intensity.upper()}")
    print()
    print("⚠️  This will generate high-volume traffic that should trigger")
    print("   your NIDS rate-based detection or DoS/DDoS classification.")
    print()
    print("Expected NIDS behavior:")
    print("  - Detect high packet rate (>200 pkt/s)")
    print("  - Classify as 'DoS/DDoS' or 'Flood Attack'")
    print("  - Block source IP (127.0.0.1)")
    print("=" * 70)
    print()
    
    input("Press Enter to start flood simulation...")
    print()
    
    # Configure based on intensity
    intensity_configs = {
        'low': {'threads': 5, 'connections_per_thread': 50, 'udp_packets': 500},
        'medium': {'threads': 10, 'connections_per_thread': 100, 'udp_packets': 2000},
        'high': {'threads': 20, 'connections_per_thread': 200, 'udp_packets': 5000}
    }
    
    config = intensity_configs.get(intensity, intensity_configs['medium'])
    
    print(f"🚀 Starting {mode.upper()} flood attack...\n")
    
    start_time = time.time()
    
    if mode == 'tcp':
        # TCP connection flood
        threads = []
        results = []
        
        print(f"   Launching {config['threads']} attack threads...")
        print(f"   Each thread will make {config['connections_per_thread']} connections")
        print()
        
        for i in range(config['threads']):
            t = threading.Thread(
                target=lambda tid=i: results.append(
                    connection_flood(target, port, config['connections_per_thread'], tid)
                )
            )
            t.start()
            threads.append(t)
            print(f"   ✅ Thread {i+1}/{config['threads']} started")
            time.sleep(0.05)  # Small delay between thread starts
        
        print(f"\n   ⏳ Waiting for all threads to complete...")
        
        for t in threads:
            t.join()
        
        total_successful = sum(r[0] for r in results)
        total_failed = sum(r[1] for r in results)
        
        elapsed = time.time() - start_time
        
        print()
        print("=" * 70)
        print("✅ TCP FLOOD COMPLETE")
        print("=" * 70)
        print(f"Total connection attempts: {total_successful + total_failed}")
        print(f"Successful: {total_successful}")
        print(f"Failed: {total_failed}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Connection rate: {(total_successful + total_failed)/elapsed:.0f} connections/sec")
        
    elif mode == 'udp':
        # UDP flood
        packets = config['udp_packets']
        packet_size = 1024
        
        print(f"   Sending {packets} UDP packets ({packet_size} bytes each)...")
        print()
        
        sent = udp_flood(target, port, packets, packet_size)
        
        elapsed = time.time() - start_time
        
        print()
        print("=" * 70)
        print("✅ UDP FLOOD COMPLETE")
        print("=" * 70)
        print(f"Packets sent: {sent}/{packets}")
        print(f"Packet size: {packet_size} bytes")
        print(f"Total data: {sent * packet_size / 1024:.2f} KB")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Packet rate: {sent/elapsed:.0f} packets/sec")
    
    print()
    print("📊 CHECK YOUR NIDS NOW:")
    print("   - Client console should show high packet rate")
    print("   - Should detect 'DoS/DDoS' or 'Flood Attack'")
    print("   - 127.0.0.1 will likely be blocked")
    print()
    print("⚠️  To unblock localhost:")
    print("   Type 'unblock 127.0.0.1' in the client console")
    print("=" * 70)


def syn_flood_warning():
    """Display warning about SYN flood requirement"""
    print("=" * 70)
    print("🚨 SYN FLOOD ATTACK SIMULATOR")
    print("=" * 70)
    print()
    print("⚠️  SYN flood requires Scapy and Administrator privileges.")
    print()
    print("To run SYN flood:")
    print("  1. Install Scapy: pip install scapy")
    print("  2. Run as Administrator")
    print("  3. Use test_synflood.py script")
    print()
    print("SYN flood will:")
    print("  - Send TCP SYN packets without completing handshake")
    print("  - Trigger DoS/DDoS detection")
    print("  - Block source IP")
    print("=" * 70)


def main():
    print("\n🎯 NIDS Testing - Traffic Flood Simulator\n")
    
    print("Select attack type:")
    print("  1. TCP Connection Flood (Low intensity)")
    print("  2. TCP Connection Flood (Medium intensity)")
    print("  3. TCP Connection Flood (High intensity)")
    print("  4. UDP Packet Flood (Low intensity)")
    print("  5. UDP Packet Flood (Medium intensity)")
    print("  6. UDP Packet Flood (High intensity)")
    print("  7. SYN Flood (requires Scapy)")
    print()
    
    try:
        choice = input("Enter choice (1-7): ").strip()
        
        if choice == '1':
            traffic_flood_test(mode='tcp', intensity='low')
        elif choice == '2':
            traffic_flood_test(mode='tcp', intensity='medium')
        elif choice == '3':
            traffic_flood_test(mode='tcp', intensity='high')
        elif choice == '4':
            traffic_flood_test(mode='udp', intensity='low')
        elif choice == '5':
            traffic_flood_test(mode='udp', intensity='medium')
        elif choice == '6':
            traffic_flood_test(mode='udp', intensity='high')
        elif choice == '7':
            syn_flood_warning()
        else:
            print("❌ Invalid choice")
            
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
