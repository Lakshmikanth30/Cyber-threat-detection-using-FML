"""
ENHANCED IP BLOCK MANAGER WITH SERVER SYNC (FIXED)
Location: E:\my nids\federated\manage_blocks.py

FIXES:
- Better file update verification
- More detailed error messages
- Confirms file was actually updated before proceeding
"""

import subprocess
import json
import os
import re
import socketio
import time
from datetime import datetime

# Configuration
BLOCKED_IPS_FILE = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\federated\blocked_ips.json"
ALLOWED_IPS_FILE = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\federated\allowed_ips.json"
FIREWALL_RULE_PREFIX = "NIDS_Block_"

# Server connection
SERVER_HOST = "192.168.0.246"
SERVER_PORT = 5000
sio = None
server_connected = False

def connect_to_server():
    """Try to connect to server for sync"""
    global sio, server_connected
    
    try:
        sio = socketio.Client(reconnection=False)
        
        @sio.event
        def connect():
            global server_connected
            server_connected = True
            print(f"   ✅ Connected to server at {SERVER_HOST}:{SERVER_PORT}")
        
        @sio.event
        def disconnect():
            global server_connected
            server_connected = False
        
        @sio.on('sync_unblock_ip')
        def on_sync_unblock(data):
            """Confirm unblock was broadcast"""
            print(f"   ✅ Server confirmed: Unblock broadcast sent to all clients")
        
        sio.connect(f"http://{SERVER_HOST}:{SERVER_PORT}", wait_timeout=5)
        time.sleep(1)
        
        if server_connected:
            sio.emit('register_client', {
                'client_id': 'manage_blocks_tool',
                'client_ip': 'localhost'
            })
            time.sleep(1)
            return True
        
    except Exception as e:
        print(f"   ℹ️  Server not available: {e}")
        print(f"   ⚠️  Changes will only affect local files (restart client to apply)")
        sio = None
        server_connected = False
        return False
    
    return False

def disconnect_from_server():
    """Disconnect from server"""
    global sio, server_connected
    if sio and server_connected:
        try:
            sio.disconnect()
        except:
            pass
    sio = None
    server_connected = False

def sync_unblock_to_server(ip_address):
    """Send unblock command to server"""
    global sio, server_connected
    
    if not server_connected or not sio:
        return False
    
    try:
        print(f"   📤 Sending unblock request to server...")
        sio.emit('unblock_ip', {
            'client_id': 'manage_blocks_tool',
            'ip_address': ip_address
        })
        time.sleep(2)
        return True
    except Exception as e:
        print(f"   ⚠️  Server sync failed: {e}")
        return False

def get_firewall_blocked_ips():
    """Get blocked IPs from Windows Firewall"""
    blocked_ips = set()
    try:
        cmd = 'netsh advfirewall firewall show rule name=all'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=15)
        output = result.stdout.decode('utf-8', errors='ignore')
        
        lines = output.split('\n')
        for line in lines:
            if 'Rule Name:' in line and FIREWALL_RULE_PREFIX in line:
                match = re.search(r'(\d+)_(\d+)_(\d+)_(\d+)', line)
                if match:
                    ip = '.'.join(match.groups())
                    blocked_ips.add(ip)
        
        return blocked_ips
    except Exception as e:
        print(f"⚠️  Error reading firewall: {e}")
        return set()

def get_blocked_ips():
    """Get blocked IPs from JSON file"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('blocked_ips', []))
        except Exception as e:
            print(f"⚠️  Error reading blocked IPs file: {e}")
    return set()

def get_allowed_ips():
    """Get temporarily allowed IPs"""
    if os.path.exists(ALLOWED_IPS_FILE):
        try:
            with open(ALLOWED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('allowed_ips', []))
        except:
            pass
    return set()

def save_allowed_ips(allowed_set):
    """Save allowed IPs to file"""
    try:
        os.makedirs(os.path.dirname(ALLOWED_IPS_FILE), exist_ok=True)
        with open(ALLOWED_IPS_FILE, 'w') as f:
            json.dump({
                'allowed_ips': list(allowed_set),
                'note': 'These IPs are temporarily allowed for current session only.',
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ Error saving allowed IPs: {e}")
        return False

def remove_from_blocked_file(ip_address):
    """Remove IP from blocked_ips.json - WITH VERIFICATION"""
    if not os.path.exists(BLOCKED_IPS_FILE):
        print(f"   ℹ️  Blocked IPs file doesn't exist")
        return False
    
    try:
        # Read current file
        print(f"   📖 Reading blocked IPs file...")
        with open(BLOCKED_IPS_FILE, 'r') as f:
            data = json.load(f)
        
        blocked_ips = set(data.get('blocked_ips', []))
        print(f"   📊 File currently has {len(blocked_ips)} blocked IPs")
        
        if ip_address not in blocked_ips:
            print(f"   ℹ️  {ip_address} is not in the blocked list")
            return False
        
        # Remove the IP
        print(f"   🗑️  Removing {ip_address} from list...")
        blocked_ips.remove(ip_address)
        data['blocked_ips'] = list(blocked_ips)
        
        # Also reset threat score
        if 'threat_scores' in data and ip_address in data['threat_scores']:
            print(f"   🗑️  Removing threat score...")
            del data['threat_scores'][ip_address]
        
        # Update timestamp
        data['timestamp'] = datetime.now().isoformat()
        
        # Write back to file
        print(f"   💾 Writing updated file...")
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        # VERIFY the write was successful
        print(f"   ✔️  Verifying file was updated...")
        with open(BLOCKED_IPS_FILE, 'r') as f:
            verify_data = json.load(f)
        
        verify_blocked = set(verify_data.get('blocked_ips', []))
        
        if ip_address in verify_blocked:
            print(f"   ❌ VERIFICATION FAILED: IP still in file!")
            return False
        
        print(f"   ✅ File updated successfully - {ip_address} removed")
        print(f"   📊 File now has {len(verify_blocked)} blocked IPs")
        return True
        
    except Exception as e:
        print(f"   ❌ Error updating blocked file: {e}")
        import traceback
        traceback.print_exc()
        return False

def unblock_ip_firewall(ip_address):
    """Remove firewall rules for IP"""
    try:
        rule_name_base = f"{FIREWALL_RULE_PREFIX}{ip_address.replace('.', '_')}"
        
        success = False
        
        # Try with _IN suffix
        cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name_base}_IN"'
        result_in = subprocess.run(cmd_in, shell=True, capture_output=True, timeout=5)
        if result_in.returncode == 0:
            print(f"   ✅ Removed inbound rule")
            success = True
        
        # Try with _OUT suffix
        cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name_base}_OUT"'
        result_out = subprocess.run(cmd_out, shell=True, capture_output=True, timeout=5)
        if result_out.returncode == 0:
            print(f"   ✅ Removed outbound rule")
            success = True
        
        # Also try without suffix (in case of old format)
        cmd_old = f'netsh advfirewall firewall delete rule name="{rule_name_base}"'
        result_old = subprocess.run(cmd_old, shell=True, capture_output=True, timeout=5)
        if result_old.returncode == 0:
            print(f"   ✅ Removed old format rule")
            success = True
        
        if not success:
            print(f"   ℹ️  No firewall rules found for {ip_address}")
        
        return success
        
    except Exception as e:
        print(f"   ⚠️  Firewall error: {e}")
        return False

def unblock_ip_permanent(ip_address):
    """Permanently unblock IP - WITH BETTER VERIFICATION"""
    print(f"\n{'='*80}")
    print(f"🔓 PERMANENTLY UNBLOCKING: {ip_address}")
    print(f"{'='*80}")
    print("   This IP will be treated as normal unless it attacks again")
    
    # Try to connect to server first
    print(f"\n🔄 Checking server connection...")
    connect_to_server()
    
    file_updated = False
    firewall_updated = False
    
    # Step 1: Remove from firewall
    print(f"\n📝 Step 1: Removing firewall rules...")
    if unblock_ip_firewall(ip_address):
        firewall_updated = True
    
    # Step 2: Remove from blocked_ips.json
    print(f"\n📝 Step 2: Updating blocked IPs file...")
    if remove_from_blocked_file(ip_address):
        file_updated = True
    
    # Step 3: Remove from allowed list (if present)
    print(f"\n📝 Step 3: Checking allowed list...")
    allowed = get_allowed_ips()
    if ip_address in allowed:
        allowed.remove(ip_address)
        save_allowed_ips(allowed)
        print(f"   ✅ Removed from allowed list")
    else:
        print(f"   ℹ️  Not in allowed list")
    
    # Step 4: Sync to server
    if server_connected:
        print(f"\n📝 Step 4: Syncing to server and clients...")
        if sync_unblock_to_server(ip_address):
            print(f"   ✅ Server notified - all clients will update automatically")
        else:
            print(f"   ⚠️  Server sync failed")
    else:
        print(f"\n📝 Step 4: Server sync...")
        print(f"   ⚠️  Server not connected - restart clients to apply changes")
    
    disconnect_from_server()
    
    # Final status
    print(f"\n{'='*80}")
    print(f"📊 UNBLOCK SUMMARY:")
    print(f"{'='*80}")
    print(f"   File updated:      {'✅ Yes' if file_updated else '❌ No'}")
    print(f"   Firewall updated:  {'✅ Yes' if firewall_updated else '❌ No'}")
    print(f"   Server synced:     {'✅ Yes' if server_connected else '⚠️  Offline'}")
    
    if file_updated or firewall_updated:
        print(f"\n✅ SUCCESS: {ip_address} has been unblocked!")
        if server_connected:
            print(f"   ✅ All connected clients have been updated")
        else:
            print(f"   ⚠️  Restart client.py to see changes")
        return True
    else:
        print(f"\n⚠️  WARNING: {ip_address} was not blocked or couldn't be unblocked")
        return False

def allow_ip_temporary(ip_address):
    """Temporarily allow IP (for current session only)"""
    print(f"\n✅ TEMPORARILY ALLOWING: {ip_address}")
    print("   This IP will NOT be blocked during current session")
    print("   Will be cleared when client restarts")
    
    success = False
    
    if unblock_ip_firewall(ip_address):
        success = True
    
    if remove_from_blocked_file(ip_address):
        success = True
    
    allowed = get_allowed_ips()
    allowed.add(ip_address)
    if save_allowed_ips(allowed):
        print(f"   ✅ Added to temporary allowed list")
        success = True
    
    if success:
        print(f"\n✅ {ip_address} allowed for current session!")
        print("   ⚠️  Will be re-evaluated when client restarts")
        return True
    else:
        print(f"\n⚠️  Could not allow {ip_address}")
        return False

def test_ping(ip_address):
    """Test ping to IP"""
    print(f"\n🔍 Pinging {ip_address}...")
    try:
        cmd = f"ping -n 2 -w 1000 {ip_address}"
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
        output = result.stdout.decode('utf-8', errors='ignore')
        
        if "Reply from" in output:
            print(f"✅ REACHABLE - {ip_address} is responding")
            return True
        elif "Request timed out" in output or "Destination host unreachable" in output:
            print(f"🚫 BLOCKED/UNREACHABLE - {ip_address} not responding")
            return False
        else:
            print(f"⚠️  Unclear result")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def show_status():
    """Show complete status"""
    print(f"\n{'='*80}")
    print(f"📊 IP BLOCK STATUS")
    print(f"{'='*80}")
    
    blocked = get_blocked_ips()
    firewall = get_firewall_blocked_ips()
    allowed = get_allowed_ips()
    
    all_blocked = blocked.union(firewall)
    
    print(f"\n🚫 BLOCKED IPs: {len(all_blocked)}")
    if all_blocked:
        for ip in sorted(all_blocked):
            in_file = "✅" if ip in blocked else "❌"
            in_fw = "✅" if ip in firewall else "❌"
            print(f"   {ip:<18} [File: {in_file}] [Firewall: {in_fw}]")
    else:
        print(f"   None")
    
    print(f"\n✅ ALLOWED IPs (Current Session): {len(allowed)}")
    if allowed:
        for ip in sorted(allowed):
            print(f"   {ip}")
    else:
        print(f"   None")
    
    print(f"\n{'='*80}")

def manage_ip(ip_address):
    """Manage specific IP"""
    blocked = get_blocked_ips()
    firewall = get_firewall_blocked_ips()
    allowed = get_allowed_ips()
    
    is_blocked = ip_address in blocked or ip_address in firewall
    is_allowed = ip_address in allowed
    
    print(f"\n{'='*80}")
    print(f"📋 IP: {ip_address}")
    print(f"{'='*80}")
    
    print(f"\nStatus:")
    print(f"   Blocked (File):     {'✅ Yes' if ip_address in blocked else '❌ No'}")
    print(f"   Blocked (Firewall): {'✅ Yes' if ip_address in firewall else '❌ No'}")
    print(f"   Allowed (Temp):     {'✅ Yes' if is_allowed else '❌ No'}")
    
    if is_allowed:
        print(f"\n💡 This IP is currently ALLOWED (temporary for this session)")
    elif is_blocked:
        print(f"\n🚫 This IP is currently BLOCKED")
    else:
        print(f"\n✅ This IP is NOT blocked")
    
    test_ping(ip_address)
    
    print(f"\n{'='*80}")
    print(f"Options:")
    
    if is_blocked or is_allowed:
        print(f"  1. Unblock PERMANENTLY (syncs to server & all clients)")
        print(f"  2. Allow TEMPORARILY (current session only)")
        print(f"  3. Test ping again")
        print(f"  4. Return to menu")
    else:
        print(f"  1. Test ping")
        print(f"  2. Return to menu")
    
    choice = input("\nChoice > ").strip()
    
    if (is_blocked or is_allowed) and choice == '1':
        confirm = input(f"\nPermanently unblock {ip_address}? (yes/no) > ").strip().lower()
        if confirm == 'yes':
            unblock_ip_permanent(ip_address)
            input("\nPress Enter to continue...")
    
    elif (is_blocked or is_allowed) and choice == '2':
        confirm = input(f"\nTemporarily allow {ip_address}? (yes/no) > ").strip().lower()
        if confirm == 'yes':
            allow_ip_temporary(ip_address)
            input("\nPress Enter to continue...")
    
    elif choice == '3' or (not is_blocked and not is_allowed and choice == '1'):
        test_ping(ip_address)
        input("\nPress Enter to continue...")

def bulk_operations():
    """Bulk unblock/allow operations"""
    blocked = get_blocked_ips()
    firewall = get_firewall_blocked_ips()
    
    all_blocked = sorted(list(blocked.union(firewall)))
    
    if not all_blocked:
        print(f"\n✅ No blocked IPs found!")
        input("\nPress Enter to continue...")
        return
    
    print(f"\n{'='*80}")
    print(f"📋 BLOCKED IPs ({len(all_blocked)} total)")
    print(f"{'='*80}")
    
    print(f"\n{'No.':<5} {'IP Address':<18} {'In File':<10} {'In Firewall':<15}")
    print("-" * 60)
    
    for i, ip in enumerate(all_blocked, 1):
        in_file = "✅" if ip in blocked else "❌"
        in_fw = "✅" if ip in firewall else "❌"
        print(f"{i:<5} {ip:<18} {in_file:<10} {in_fw:<15}")
    
    print(f"\n{'='*80}")
    print(f"Bulk Operations:")
    print(f"  1. Unblock ALL (permanently, syncs to server)")
    print(f"  2. Allow ALL (temporarily)")
    print(f"  3. Unblock specific IP")
    print(f"  4. Allow specific IP")
    print(f"  5. Return to menu")
    
    choice = input("\nChoice > ").strip()
    
    if choice == '1':
        confirm = input(f"\n⚠️  Permanently unblock ALL {len(all_blocked)} IPs? (yes/no) > ").strip().lower()
        if confirm == 'yes':
            for ip in all_blocked:
                unblock_ip_permanent(ip)
                print()
            print(f"✅ Done!")
            input("\nPress Enter to continue...")
    
    elif choice == '2':
        confirm = input(f"\n⚠️  Temporarily allow ALL {len(all_blocked)} IPs? (yes/no) > ").strip().lower()
        if confirm == 'yes':
            for ip in all_blocked:
                allow_ip_temporary(ip)
            print(f"\n✅ Done!")
            input("\nPress Enter to continue...")
    
    elif choice == '3':
        num = input(f"Enter number (1-{len(all_blocked)}) > ").strip()
        if num.isdigit() and 1 <= int(num) <= len(all_blocked):
            ip = all_blocked[int(num) - 1]
            confirm = input(f"\nPermanently unblock {ip}? (yes/no) > ").strip().lower()
            if confirm == 'yes':
                unblock_ip_permanent(ip)
                input("\nPress Enter to continue...")
    
    elif choice == '4':
        num = input(f"Enter number (1-{len(all_blocked)}) > ").strip()
        if num.isdigit() and 1 <= int(num) <= len(all_blocked):
            ip = all_blocked[int(num) - 1]
            confirm = input(f"\nTemporarily allow {ip}? (yes/no) > ").strip().lower()
            if confirm == 'yes':
                allow_ip_temporary(ip)
                input("\nPress Enter to continue...")

def clear_allowed_ips():
    """Clear all temporarily allowed IPs"""
    allowed = get_allowed_ips()
    
    if not allowed:
        print(f"\n✅ No allowed IPs to clear")
        input("\nPress Enter to continue...")
        return
    
    print(f"\n{'='*80}")
    print(f"📋 TEMPORARILY ALLOWED IPs ({len(allowed)} total)")
    print(f"{'='*80}")
    for ip in sorted(allowed):
        print(f"   {ip}")
    
    confirm = input(f"\n⚠️  Clear all {len(allowed)} allowed IPs? (yes/no) > ").strip().lower()
    
    if confirm == 'yes':
        save_allowed_ips(set())
        print(f"\n✅ Allowed IPs list cleared!")
        input("\nPress Enter to continue...")

def main_menu():
    """Main menu"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("\n" + "="*80)
        print("🛡️  ENHANCED IP BLOCK MANAGER (FIXED - WITH SERVER SYNC)")
        print("="*80)
        
        blocked = get_blocked_ips()
        firewall = get_firewall_blocked_ips()
        allowed = get_allowed_ips()
        all_blocked = blocked.union(firewall)
        
        print(f"\n📊 Quick Status:")
        print(f"   Blocked IPs: {len(all_blocked)}")
        print(f"   Allowed IPs (temp): {len(allowed)}")
        
        print(f"\n{'='*80}")
        print(f"Main Menu:")
        print(f"  1. Show complete status")
        print(f"  2. Manage specific IP")
        print(f"  3. Bulk operations")
        print(f"  4. Clear allowed IPs")
        print(f"  5. Test ping")
        print(f"  6. Exit")
        
        choice = input("\nChoice > ").strip()
        
        if choice == '1':
            show_status()
            input("\nPress Enter to continue...")
        
        elif choice == '2':
            ip = input("\nEnter IP address > ").strip()
            if ip:
                manage_ip(ip)
        
        elif choice == '3':
            bulk_operations()
        
        elif choice == '4':
            clear_allowed_ips()
        
        elif choice == '5':
            ip = input("\nEnter IP address > ").strip()
            if ip:
                test_ping(ip)
                input("\nPress Enter to continue...")
        
        elif choice == '6':
            print("\n👋 Exiting...")
            disconnect_from_server()
            break
        
        else:
            print("❌ Invalid choice")
            input("\nPress Enter to continue...")

if __name__ == '__main__':
    print("\n" + "="*80)
    print("⚠️  IMPORTANT: Run as Administrator!")
    print("="*80)
    print("\n💡 FIXED: Better file update verification")
    print("💡 FIXED: More detailed error messages")
    input("\nPress Enter to continue...")
    
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...")
        disconnect_from_server()