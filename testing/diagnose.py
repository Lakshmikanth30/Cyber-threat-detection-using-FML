"""
SYSTEM DIAGNOSTIC TOOL
======================
Comprehensive diagnostic to check NIDS server/client status.
Run this to troubleshoot issues with attack detection.
"""

import requests
import json
import subprocess
import os
import sys

def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def check_server_status(base_url='http://localhost:5000'):
    """Check server API status"""
    print_section("📡 SERVER STATUS CHECK")
    
    try:
        # Check main status endpoint
        r = requests.get(f'{base_url}/api/status', timeout=5)
        if r.status_code == 200:
            data = r.json()
            
            print(f"✅ Server is RUNNING")
            print(f"\nUptime: {data.get('uptime', 0):.2f} seconds")
            print(f"Status: {data.get('status', 'unknown')}")
            print(f"\n📊 Global Statistics:")
            
            stats = data.get('global_stats', {})
            print(f"   Total Attacks Detected: {stats.get('total_attacks_detected', 0)}")
            print(f"   Total IPs Blocked: {stats.get('total_ips_blocked', 0)}")
            print(f"   Total Packets Processed: {stats.get('total_packets_processed', 0)}")
            print(f"   Clients Connected: {stats.get('clients_connected', 0)}")
            print(f"   Federated Rounds: {stats.get('federated_rounds', 0)}")
            print(f"   Global Accuracy: {stats.get('global_accuracy', 0)*100:.2f}%")
            
            print(f"\n🎯 Attack Types:")
            for attack_type, count in stats.get('attack_types', {}).items():
                print(f"   {attack_type}: {count}")
            
            return True
        else:
            print(f"⚠️  Server responded with status code: {r.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server")
        print(f"   Make sure server is running at {base_url}")
        print(f"   Run: START_SERVER.bat")
        return False
    except Exception as e:
        print(f"❌ Error checking server: {e}")
        return False

def check_clients(base_url='http://localhost:5000'):
    """Check connected clients"""
    print_section("👥 CONNECTED CLIENTS")
    
    try:
        r = requests.get(f'{base_url}/api/clients', timeout=5)
        if r.status_code == 200:
            data = r.json()
            count = data.get('count', 0)
            
            if count == 0:
                print("⚠️  NO CLIENTS CONNECTED")
                print("\nPossible reasons:")
                print("   - Client not started (run START_CLIENT.bat)")
                print("   - Client crashed during startup")
                print("   - Socket.IO connection failed")
                print("   - Firewall blocking connection")
                return False
            else:
                print(f"✅ {count} client(s) connected\n")
                
                for client_id, client_data in data.get('clients', {}).items():
                    status = client_data.get('status', 'unknown')
                    last_update = client_data.get('last_update', 'N/A')
                    
                    status_icon = "✅" if status == "online" else "⚠️"
                    print(f"{status_icon} Client: {client_id}")
                    print(f"   Status: {status}")
                    print(f"   Last Update: {last_update}")
                    
                    if 'stats' in client_data:
                        stats = client_data['stats']
                        print(f"   Stats:")
                        for key, value in stats.items():
                            print(f"      {key}: {value}")
                    print()
                
                return True
        else:
            print(f"⚠️  Error: Status code {r.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking clients: {e}")
        return False

def check_recent_attacks(base_url='http://localhost:5000'):
    """Check recent attacks"""
    print_section("🚨 RECENT ATTACKS")
    
    try:
        r = requests.get(f'{base_url}/api/attacks/recent', timeout=5)
        if r.status_code == 200:
            data = r.json()
            attacks = data.get('attacks', [])
            count = len(attacks)
            
            if count == 0:
                print("⚠️  NO ATTACKS DETECTED YET")
                print("\nThis could mean:")
                print("   ✅ Your network is clean (good!)")
                print("   ⚠️  Client isn't processing traffic")
                print("   ⚠️  Detection thresholds too high")
                print("   ⚠️  No attack-like traffic present")
                print("\n💡 Try:")
                print("   - Run test_portscan.py to simulate attacks")
                print("   - Run test_traffic_flood.py for flood detection")
                print("   - Lower CONFIDENCE_THRESHOLD in config.py (testing only)")
                return False
            else:
                print(f"✅ {count} attack(s) detected\n")
                
                # Show last 10 attacks
                for i, attack in enumerate(attacks[:10], 1):
                    timestamp = attack.get('timestamp', 'N/A')
                    client_id = attack.get('client_id', 'unknown')
                    ip = attack.get('ip_address', 'unknown')
                    attack_type = attack.get('attack_type', 'unknown')
                    confidence = attack.get('confidence', 0) * 100
                    
                    print(f"{i}. {timestamp}")
                    print(f"   Client: {client_id}")
                    print(f"   Source IP: {ip}")
                    print(f"   Type: {attack_type}")
                    print(f"   Confidence: {confidence:.1f}%")
                    print()
                
                if count > 10:
                    print(f"   ... and {count - 10} more attacks")
                
                return True
        else:
            print(f"⚠️  Error: Status code {r.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking attacks: {e}")
        return False

def check_blocked_ips(base_url='http://localhost:5000'):
    """Check blocked IPs"""
    print_section("🚫 BLOCKED IPs")
    
    try:
        r = requests.get(f'{base_url}/api/blocked_ips', timeout=5)
        if r.status_code == 200:
            data = r.json()
            blocked = data.get('blocked_ips', [])
            count = len(blocked)
            
            if count == 0:
                print("✅ No IPs currently blocked")
            else:
                print(f"🚫 {count} IP(s) blocked:\n")
                for ip in blocked[:20]:
                    print(f"   • {ip}")
                
                if count > 20:
                    print(f"   ... and {count - 20} more")
            
            return True
        else:
            print(f"⚠️  Error: Status code {r.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking blocked IPs: {e}")
        return False

def check_firewall_rules():
    """Check Windows Firewall rules"""
    print_section("🔥 FIREWALL RULES CHECK")
    
    try:
        cmd = 'netsh advfirewall firewall show rule name=all | findstr "NIDS_Block"'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
        output = result.stdout.decode('utf-8', errors='ignore')
        
        if output.strip():
            lines = output.strip().split('\n')
            count = len(lines)
            print(f"✅ Found {count} NIDS firewall rule(s)\n")
            
            # Show first 10 rules
            for line in lines[:10]:
                print(f"   {line.strip()}")
            
            if count > 10:
                print(f"   ... and {count - 10} more rules")
        else:
            print("⚠️  No NIDS firewall rules found")
            print("\nThis means:")
            print("   - No IPs have been blocked yet, OR")
            print("   - Firewall rules were manually removed")
        
        return True
    except Exception as e:
        print(f"⚠️  Could not check firewall: {e}")
        print("   (This is OK if not running as Administrator)")
        return False

def check_config_files():
    """Check configuration files"""
    print_section("📁 CONFIGURATION FILES")
    
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    files_to_check = {
        'Config': os.path.join(base_path, 'federated', 'config.py'),
        'Blocked IPs': os.path.join(base_path, 'federated', 'blocked_ips.json'),
        'Model': os.path.join(base_path, 'models', 'hybrid_federated_optimized.pkl'),
        'Log': os.path.join(base_path, 'federated', 'nids.log')
    }
    
    for name, path in files_to_check.items():
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"✅ {name}: Found ({size:,} bytes)")
            
            if name == 'Blocked IPs' and size > 0:
                try:
                    with open(path, 'r') as f:
                        data = json.load(f)
                        blocked = data.get('blocked_ips', [])
                        print(f"   Contains {len(blocked)} blocked IP(s)")
                except:
                    pass
        else:
            print(f"❌ {name}: NOT FOUND")
            print(f"   Expected at: {path}")

def check_config_values():
    """Check critical config values"""
    print_section("⚙️  CONFIGURATION VALUES")
    
    try:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_path, 'federated', 'config.py')
        
        # Read config file
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Extract key values
        import re
        
        def extract_value(key):
            match = re.search(f'{key}\s*=\s*(.+)', content)
            return match.group(1).strip() if match else 'NOT FOUND'
        
        confidence = extract_value('CONFIDENCE_THRESHOLD')
        threat_limit = extract_value('THREAT_SCORE_LIMIT')
        min_packets = extract_value('MIN_PACKETS_FOR_CLASSIFICATION')
        auto_block = extract_value('AUTO_BLOCK_ENABLED')
        
        print(f"CONFIDENCE_THRESHOLD = {confidence}")
        print(f"THREAT_SCORE_LIMIT = {threat_limit}")
        print(f"MIN_PACKETS_FOR_CLASSIFICATION = {min_packets}")
        print(f"AUTO_BLOCK_ENABLED = {auto_block}")
        
        # Check if values are reasonable
        try:
            conf_val = float(confidence)
            if conf_val > 0.9:
                print(f"\n⚠️  WARNING: Confidence threshold is very high ({conf_val})")
                print("   This may prevent attack detection")
                print("   Consider lowering to 0.5-0.75 for testing")
        except:
            pass
        
        return True
    except Exception as e:
        print(f"⚠️  Could not read config: {e}")
        return False

def provide_recommendations():
    """Provide troubleshooting recommendations"""
    print_section("💡 RECOMMENDATIONS")
    
    print("To see attack data on the dashboard:\n")
    
    print("1️⃣  VERIFY SYSTEM IS RUNNING:")
    print("   ✓ Server running (START_SERVER.bat)")
    print("   ✓ Client running (START_CLIENT.bat)")
    print("   ✓ Client shows 'Captured' > 0 packets")
    print()
    
    print("2️⃣  GENERATE TEST TRAFFIC:")
    print("   • Run: python testing/test_portscan.py")
    print("   • Run: python testing/test_traffic_flood.py")
    print("   • Run: python testing/test_dashboard_inject.py (bypass ML)")
    print()
    
    print("3️⃣  FOR TESTING, LOWER THRESHOLDS:")
    print("   Edit federated/config.py:")
    print("   CONFIDENCE_THRESHOLD = 0.5  (was 0.75)")
    print("   MIN_PACKETS_FOR_CLASSIFICATION = 5  (was 15)")
    print("   Then restart client")
    print()
    
    print("4️⃣  CHECK LOGS:")
    print("   • Client console - shows packet capture")
    print("   • Server console - shows attack events")
    print("   • federated/nids.log - detailed log file")
    print()
    
    print("5️⃣  VERIFY DASHBOARD:")
    print("   • Visit: http://localhost:5000")
    print("   • Check browser console (F12) for errors")
    print("   • Verify WebSocket connection established")

def main():
    print("\n" + "=" * 70)
    print("  🔍 FEDERATED NIDS - SYSTEM DIAGNOSTIC")
    print("=" * 70)
    print("\nThis tool will check all components of your NIDS system.\n")
    
    server_url = input("Server URL (default: http://localhost:5000): ").strip()
    if not server_url:
        server_url = 'http://localhost:5000'
    
    print(f"\n🔍 Running diagnostic checks on {server_url}...\n")
    
    # Run all checks
    results = {
        'server': check_server_status(server_url),
        'clients': check_clients(server_url),
        'attacks': check_recent_attacks(server_url),
        'blocked': check_blocked_ips(server_url),
        'firewall': check_firewall_rules(),
        'config_files': check_config_files(),
        'config_values': check_config_values()
    }
    
    # Summary
    print_section("📊 DIAGNOSTIC SUMMARY")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    print(f"\nChecks Passed: {passed}/{total}\n")
    
    for check, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {check.replace('_', ' ').title()}")
    
    # Provide recommendations
    provide_recommendations()
    
    print("\n" + "=" * 70)
    print("  Diagnostic Complete")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Diagnostic cancelled")
    except Exception as e:
        print(f"\n❌ Diagnostic error: {e}")
        import traceback
        traceback.print_exc()
