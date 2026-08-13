"""
IMPROVED DASHBOARD DATA INJECTOR WITH TIME-SPREAD ATTACKS
==========================================================
This version spreads attacks over multiple minutes to populate the timeline chart.
"""

import socketio
import time
import random
from datetime import datetime, timedelta

ATTACK_TYPES = ['BruteForce', 'DoS/DDoS', 'PortScan']
FAKE_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102',
    '10.0.0.50', '10.0.0.51', '10.0.0.52',
    '172.16.0.100', '172.16.0.101', '172.16.0.102'
]

def inject_historical_attacks(server_url='http://localhost:5000', num_attacks=30):
    """
    Inject attacks spread over the last 15 minutes to populate timeline chart
    """
    print("=" * 70)
    print("📊 TIMELINE CHART POPULATOR")
    print("=" * 70)
    print(f"Server: {server_url}")
    print(f"Attacks to inject: {num_attacks}")
    print()
    print("This will create attacks spread over 15 minutes to populate")
    print("the timeline chart with realistic historical data.")
    print("=" * 70)
    print()
    
    input("Press Enter to start...")
    print()
    
    sio = socketio.Client()
    connected = False
    
    @sio.event
    def connect():
        nonlocal connected
        connected = True
        print("✅ Connected to server\n")
        sio.emit('register_client', {
            'client_id': 'test_client_timeline',
            'client_ip': '192.168.1.999'
        })
    
    @sio.event
    def disconnect():
        nonlocal connected
        connected = False
    
    @sio.on('initial_sync')
    def on_sync(data):
        print("✅ Registration confirmed\n")
    
    print(f"🔄 Connecting to {server_url}...")
    try:
        sio.connect(server_url, wait_timeout=10)
        time.sleep(2)
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return
    
    if not connected:
        print("❌ Could not connect")
        return
    
    print("🚀 Injecting attacks with time spread...\n")
    
    # Generate attacks spread over 15 minutes
    now = datetime.now()
    attacks_timeline = []
    
    for i in range(num_attacks):
        # Spread attacks over last 15 minutes
        minutes_ago = random.randint(0, 15)
        attack_time = now - timedelta(minutes=minutes_ago)
        
        attack = {
            'timestamp': attack_time,
            'type': random.choice(ATTACK_TYPES),
            'ip': random.choice(FAKE_IPS),
            'confidence': random.uniform(0.75, 0.99)
        }
        attacks_timeline.append(attack)
    
    # Sort by time (oldest first)
    attacks_timeline.sort(key=lambda x: x['timestamp'])
    
    # Inject attacks rapidly
    for i, attack in enumerate(attacks_timeline, 1):
        # Manually set timestamp in the attack data
        attack_data = {
            'client_id': 'test_client_timeline',
            'ip_address': attack['ip'],
            'attack_type': attack['type'],
            'confidence': attack['confidence'],
            'threat_score': random.randint(1, 3),
            'timestamp': attack['timestamp'].isoformat()
        }
        
        sio.emit('attack_detected', attack_data)
        
        if i % 5 == 0:
            print(f"   📤 Injected {i}/{num_attacks} attacks...")
        
        time.sleep(0.1)  # Small delay
    
    print(f"\n✅ All {num_attacks} attacks injected!")
    print()
    print("📊 REFRESH YOUR DASHBOARD NOW")
    print("   The timeline chart should now show attack distribution")
    print("   over the last 15 minutes.")
    print()
    print("⏳ Keeping connection alive for 30 seconds...")
    print("=" * 70)
    
    time.sleep(30)
    sio.disconnect()


def inject_realtime_attacks(server_url='http://localhost:5000', duration=60):
    """
    Inject attacks in real-time over a period to see live chart updates
    """
    print("=" * 70)
    print("🔴 REAL-TIME ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Server: {server_url}")
    print(f"Duration: {duration} seconds")
    print()
    print("This will continuously send attacks to show real-time")
    print("chart updates. Watch the timeline chart animate!")
    print("=" * 70)
    print()
    
    input("Press Enter to start...")
    print()
    
    sio = socketio.Client()
    connected = False
    
    @sio.event
    def connect():
        nonlocal connected
        connected = True
        print("✅ Connected to server\n")
        sio.emit('register_client', {
            'client_id': 'test_client_realtime',
            'client_ip': '192.168.1.998'
        })
    
    print(f"🔄 Connecting to {server_url}...")
    try:
        sio.connect(server_url, wait_timeout=10)
        time.sleep(2)
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return
    
    if not connected:
        print("❌ Could not connect")
        return
    
    print(f"🚀 Starting {duration}s real-time attack stream...")
    print("   (Watch the dashboard timeline chart update live!)\n")
    
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        attack_data = {
            'client_id': 'test_client_realtime',
            'ip_address': random.choice(FAKE_IPS),
            'attack_type': random.choice(ATTACK_TYPES),
            'confidence': random.uniform(0.75, 0.99),
            'threat_score': random.randint(1, 3)
        }
        
        sio.emit('attack_detected', attack_data)
        count += 1
        
        if count % 5 == 0:
            elapsed = int(time.time() - start_time)
            print(f"   📤 {count} attacks sent | {elapsed}/{duration}s elapsed")
        
        # Random delay between attacks (2-5 seconds)
        time.sleep(random.uniform(2, 5))
    
    print(f"\n✅ Sent {count} attacks over {duration} seconds")
    print("=" * 70)
    
    time.sleep(5)
    sio.disconnect()


def main():
    print("\n🎯 Dashboard Timeline Chart Tester\n")
    
    server_url = input("Server URL (default: http://localhost:5000): ").strip()
    if not server_url:
        server_url = 'http://localhost:5000'
    
    print()
    print("Select mode:")
    print("  1. Historical Data (30 attacks over 15 minutes) - RECOMMENDED")
    print("  2. Real-time Stream (attacks every few seconds for 60s)")
    print("  3. Custom Historical")
    print()
    
    try:
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == '1':
            inject_historical_attacks(server_url, num_attacks=30)
        elif choice == '2':
            inject_realtime_attacks(server_url, duration=60)
        elif choice == '3':
            num = int(input("Number of attacks: "))
            inject_historical_attacks(server_url, num_attacks=num)
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
