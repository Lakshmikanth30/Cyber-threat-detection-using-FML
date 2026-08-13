"""
SAFE PORT SCAN SIMULATOR
========================
Simulates a port scan attack on localhost for NIDS testing.
This is SAFE and ETHICAL - only scans your own computer.

Run this while your NIDS client is running to trigger PortScan detection.
"""

import socket
import time
import sys

def port_scan_test(target="127.0.0.1", start_port=1, end_port=1000, delay=0.001):
    """
    Simulate a port scan attack
    
    Args:
        target: IP to scan (default: localhost - SAFE)
        start_port: First port to scan
        end_port: Last port to scan
        delay: Delay between scans (smaller = faster = more detectable)
    """
    print("=" * 70)
    print("🔍 PORT SCAN ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Target: {target} (SAFE - scanning yourself)")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Delay: {delay}s between ports")
    print()
    print("⚠️  This will generate suspicious traffic patterns that should")
    print("   trigger your NIDS to detect a PortScan attack.")
    print()
    print("Expected NIDS behavior:")
    print("  - Detect multiple connection attempts to different ports")
    print("  - Classify as 'PortScan' attack")
    print("  - Potentially block 127.0.0.1 (your own machine)")
    print("=" * 70)
    print()
    
    input("Press Enter to start port scan simulation...")
    print()
    
    open_ports = []
    scanned = 0
    start_time = time.time()
    
    print(f"🚀 Starting port scan...\n")
    
    for port in range(start_port, end_port + 1):
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            
            # Try to connect
            result = sock.connect_ex((target, port))
            
            if result == 0:
                open_ports.append(port)
                print(f"   ✅ Port {port} - OPEN")
            
            sock.close()
            scanned += 1
            
            # Progress indicator
            if scanned % 100 == 0:
                elapsed = time.time() - start_time
                rate = scanned / elapsed
                print(f"   📊 Progress: {scanned}/{end_port - start_port + 1} ports scanned ({rate:.0f} ports/sec)")
            
            time.sleep(delay)
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            break
        except socket.error:
            pass
        except Exception as e:
            if scanned % 100 == 0:
                print(f"   ⚠️  Error on port {port}: {e}")
    
    elapsed = time.time() - start_time
    
    print()
    print("=" * 70)
    print("✅ PORT SCAN COMPLETE")
    print("=" * 70)
    print(f"Total ports scanned: {scanned}")
    print(f"Open ports found: {len(open_ports)}")
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports[:10]))}")
        if len(open_ports) > 10:
            print(f"            ... and {len(open_ports) - 10} more")
    print(f"Time elapsed: {elapsed:.2f} seconds")
    print(f"Scan rate: {scanned/elapsed:.0f} ports/sec")
    print()
    print("📊 CHECK YOUR NIDS NOW:")
    print("   - Client console should show 'PortScan' detection")
    print("   - Server dashboard should display the attack")
    print("   - 127.0.0.1 may be blocked (expected behavior)")
    print()
    print("⚠️  If localhost gets blocked, unblock it using:")
    print("   Type 'unblock 127.0.0.1' in the client console")
    print("=" * 70)


def main():
    print("\n🎯 NIDS Testing - Port Scan Simulator\n")
    
    # Configuration
    configs = [
        {
            'name': 'Quick Test (100 ports)',
            'start': 1,
            'end': 100,
            'delay': 0.01
        },
        {
            'name': 'Medium Test (500 ports)',
            'start': 1,
            'end': 500,
            'delay': 0.005
        },
        {
            'name': 'Aggressive Test (1000 ports)',
            'start': 1,
            'end': 1000,
            'delay': 0.001
        },
        {
            'name': 'Stealth Test (100 ports, slow)',
            'start': 1,
            'end': 100,
            'delay': 0.1
        }
    ]
    
    print("Select scan mode:")
    for i, config in enumerate(configs, 1):
        print(f"  {i}. {config['name']}")
    print(f"  5. Custom")
    print()
    
    try:
        choice = input("Enter choice (1-5): ").strip()
        
        if choice in ['1', '2', '3', '4']:
            config = configs[int(choice) - 1]
            print(f"\n✅ Selected: {config['name']}\n")
            port_scan_test(
                start_port=config['start'],
                end_port=config['end'],
                delay=config['delay']
            )
        elif choice == '5':
            start = int(input("Start port (default 1): ") or "1")
            end = int(input("End port (default 1000): ") or "1000")
            delay = float(input("Delay in seconds (default 0.001): ") or "0.001")
            print()
            port_scan_test(start_port=start, end_port=end, delay=delay)
        else:
            print("❌ Invalid choice")
            return
            
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
