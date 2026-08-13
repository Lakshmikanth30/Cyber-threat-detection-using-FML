"""
DASHBOARD DATA INJECTOR
=======================
Injects fake attack data directly into the server for dashboard testing.
Use this to verify the dashboard frontend works correctly.

This bypasses the ML detection entirely - useful for UI testing.
"""

import socketio
import time
import random
from datetime import datetime

# Attack types from your NIDS
ATTACK_TYPES = ['BruteForce', 'DoS/DDoS', 'PortScan']

# Fake IP addresses for testing
FAKE_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102',
    '10.0.0.50', '10.0.0.51', '10.0.0.52',
    '172.16.0.100', '172.16.0.101', '172.16.0.102'
]

def inject_attack_data(server_url='http://127.0.0.1:5001', num_attacks=20, delay=1.0):
    """
    Inject fake attack data into the server
    
    Args:
        server_url: Server URL
        num_attacks: Number of attacks to inject
        delay: Delay between attacks (seconds)
    """
    print("=" * 70)
    print("💉 DASHBOARD DATA INJECTOR")
    print("=" * 70)
    print(f"Server: {server_url}")
    print(f"Attacks to inject: {num_attacks}")
    print(f"Delay: {delay}s between attacks")
    print()
    print("This will:")
    print("  - Connect as fake client 'test_client'")
    print("  - Send fake attack detection events")
    print("  - Block some IPs")
    print("  - Populate dashboard with test data")
    print()
    print("⚠️  Make sure your server is running!")
    print("=" * 70)
    print()
    
    input("Press Enter to start data injection...")
    print()
    
    # Create Socket.IO client
    sio = socketio.Client()
    
    connected = False
    
    @sio.event
    def connect():
        nonlocal connected
        connected = True
        print("✅ Connected to server")
        print()
        
        # Register fake client
        sio.emit('register_client', {
            'client_id': 'test_client',
            'client_ip': '192.168.1.999'
        })
        print("📝 Registered as 'test_client'")
        print()
    
    @sio.event
    def disconnect():
        nonlocal connected
        connected = False
        print("\n❌ Disconnected from server")
    
    @sio.on('initial_sync')
    def on_initial_sync(data):
        print(f"✅ Server confirmed registration")
        print(f"   Global stats: {data.get('global_stats', {})}")
        print()
    
    # Connect to server
    print(f"🔄 Connecting to {server_url}...")
    try:
        sio.connect(server_url, wait_timeout=10)
        time.sleep(2)  # Wait for registration
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print()
        print("Make sure:")
        print("  - Server is running (START_SERVER.bat)")
        print("  - Server is at http://127.0.0.1:5001")
        print("  - No firewall blocking connection")
        return
    
    if not connected:
        print("❌ Could not establish connection")
        return
    
    print("🚀 Starting attack injection...\n")
    
    blocked_ips = set()
    
    for i in range(num_attacks):
        # Generate random attack
        attack_type = random.choice(ATTACK_TYPES)
        ip_address = random.choice(FAKE_IPS)
        confidence = random.uniform(0.75, 0.99)
        threat_score = random.randint(1, 3)
        
        # Emit attack event
        attack_data = {
            'client_id': 'test_client',
            'ip_address': ip_address,
            'attack_type': attack_type,
            'confidence': confidence,
            'threat_score': threat_score
        }
        
        sio.emit('attack_detected', attack_data)
        
        print(f"📤 Attack {i+1}/{num_attacks}:")
        print(f"   Type: {attack_type}")
        print(f"   Source: {ip_address}")
        print(f"   Confidence: {confidence*100:.1f}%")
        print(f"   Threat Score: {threat_score}")
        
        # Randomly block IPs
        if threat_score >= 2 and ip_address not in blocked_ips and random.random() > 0.3:
            sio.emit('block_ip', {
                'client_id': 'test_client',
                'ip_address': ip_address,
                'reason': attack_type
            })
            blocked_ips.add(ip_address)
            print(f"   🚫 IP BLOCKED")
        
        print()
        
        time.sleep(delay)
    
    # Send some stats updates
    print("📊 Sending stats update...")
    sio.emit('stats_update', {
        'client_id': 'test_client',
        'stats': {
            'packets_captured': num_attacks * 150,
            'packets_processed': num_attacks * 140,
            'packets_dropped': num_attacks * 10,
            'flows_tracked': num_attacks * 5,
            'attacks_detected': num_attacks,
            'ml_detections': int(num_attacks * 0.7),
            'rate_detections': int(num_attacks * 0.3),
            'ips_blocked': len(blocked_ips),
            'normal_traffic': 500
        }
    })
    print()
    
    print("=" * 70)
    print("✅ DATA INJECTION COMPLETE")
    print("=" * 70)
    print(f"Total attacks injected: {num_attacks}")
    print(f"IPs blocked: {len(blocked_ips)}")
    print()
    print("📊 CHECK YOUR DASHBOARD NOW:")
    print("   URL: http://127.0.0.1:5001")
    print()
    print("You should see:")
    print("  ✅ Attack counter updated")
    print("  ✅ Recent attacks listed")
    print("  ✅ Charts showing attack timeline")
    print("  ✅ Blocked IPs listed")
    print("  ✅ Client 'test_client' connected")
    print()
    print("⏳ Keeping connection alive for 30 seconds...")
    print("   (So you can view the dashboard)")
    print("=" * 70)
    
    time.sleep(30)
    
    print("\n👋 Disconnecting...")
    sio.disconnect()


def inject_burst_attacks(server_url='http://127.0.0.1:5001'):
    """
    Inject a burst of attacks quickly to test real-time updates
    """
    print("=" * 70)
    print("💥 BURST ATTACK INJECTION")
    print("=" * 70)
    print("This will send 50 attacks in rapid succession (0.2s delay)")
    print("to test dashboard real-time update capabilities.")
    print("=" * 70)
    print()
    
    input("Press Enter to start burst injection...")
    
    inject_attack_data(
        server_url=server_url,
        num_attacks=50,
        delay=0.2
    )


def inject_slow_attacks(server_url='http://127.0.0.1:5001'):
    """
    Inject attacks slowly to simulate realistic detection
    """
    print("=" * 70)
    print("🐌 SLOW ATTACK INJECTION")
    print("=" * 70)
    print("This will send 10 attacks with 5s delay to simulate")
    print("realistic attack detection over time.")
    print("=" * 70)
    print()
    
    input("Press Enter to start slow injection...")
    
    inject_attack_data(
        server_url=server_url,
        num_attacks=10,
        delay=5.0
    )


def main():
    print("\n🎯 NIDS Testing - Dashboard Data Injector\n")
    
    server_url = input(f"Server URL (default: http://127.0.0.1:5001): ").strip()
    if not server_url:
        server_url = 'http://127.0.0.1:5001'
    
    print()
    print("Select injection mode:")
    print("  1. Normal (20 attacks, 1s delay)")
    print("  2. Burst (50 attacks, 0.2s delay)")
    print("  3. Slow (10 attacks, 5s delay)")
    print("  4. Custom")
    print()
    
    try:
        choice = input("Enter choice (1-4): ").strip()
        
        if choice == '1':
            inject_attack_data(server_url)
        elif choice == '2':
            inject_burst_attacks(server_url)
        elif choice == '3':
            inject_slow_attacks(server_url)
        elif choice == '4':
            num = int(input("Number of attacks: "))
            delay = float(input("Delay (seconds): "))
            inject_attack_data(server_url, num, delay)
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
