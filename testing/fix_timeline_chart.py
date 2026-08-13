"""
QUICK TIMELINE CHART FIXER
===========================
Sends attacks spaced over time so timeline chart populates properly.
"""

import socketio
import time
import random

def fill_timeline_chart():
    """Send attacks every 10 seconds to populate different time slots"""
    
    print("=" * 70)
    print("📊 TIMELINE CHART FILLER")
    print("=" * 70)
    print()
    print("This will send 1 attack every 10 seconds for 2 minutes.")
    print("This creates attacks across multiple time slots on the timeline chart.")
    print()
    print("⏰ Duration: ~2 minutes")
    print("📊 Result: Timeline chart will show trend line")
    print("=" * 70)
    print()
    
    input("Press Enter to start (keep dashboard open in browser)...")
    print()
    
    sio = socketio.Client()
    
    @sio.event
    def connect():
        print("✅ Connected\n")
        sio.emit('register_client', {
            'client_id': 'timeline_filler',
            'client_ip': '192.168.1.999'
        })
    
    print("🔄 Connecting...")
    try:
        sio.connect('http://localhost:5000', wait_timeout=10)
        time.sleep(2)
    except Exception as e:
        print(f"❌ Failed: {e}")
        return
    
    print("🚀 Starting timed attack sequence...")
    print("   (Watch your dashboard - refresh if needed)\n")
    
    attack_types = ['PortScan', 'DoS/DDoS', 'BruteForce']
    ips = ['192.168.1.100', '192.168.1.101', '10.0.0.50', '172.16.0.100']
    
    for i in range(12):  # 12 attacks over 2 minutes
        attack_data = {
            'client_id': 'timeline_filler',
            'ip_address': random.choice(ips),
            'attack_type': random.choice(attack_types),
            'confidence': random.uniform(0.75, 0.95),
            'threat_score': random.randint(1, 2)
        }
        
        sio.emit('attack_detected', attack_data)
        
        current_time = time.strftime("%H:%M:%S")
        print(f"   [{current_time}] Attack {i+1}/12 sent - {attack_data['attack_type']}")
        
        if i < 11:  # Don't sleep after last one
            print(f"   ⏳ Waiting 10 seconds...")
            time.sleep(10)
    
    print()
    print("=" * 70)
    print("✅ COMPLETE!")
    print("=" * 70)
    print()
    print("📊 REFRESH YOUR DASHBOARD NOW")
    print("   The timeline chart should now show a line with multiple points")
    print("   Each point represents attacks in that minute")
    print()
    
    time.sleep(5)
    sio.disconnect()
    print("👋 Done!")


if __name__ == "__main__":
    try:
        fill_timeline_chart()
    except KeyboardInterrupt:
        print("\n\n👋 Cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
