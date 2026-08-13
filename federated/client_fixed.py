"""
FEDERATED NIDS - CLIENT (FIXED SOCKET.IO CONNECTION)
"""

import socketio
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import threading
import subprocess
import socket
import json
from collections import defaultdict
from datetime import datetime
import config
import os
import sys
import re

# =====================================================
# CONFIGURATION
# =====================================================

CLIENT_ID = "laptop_2"  # ← CHANGE THIS FOR EACH LAPTOP

# =====================================================
# WHITELIST
# =====================================================

WHITELIST_IPS = {
    '127.0.0.1',
    '192.168.0.1',
    config.SERVER_HOST
}

print("=" * 80)
print(f"🖥️  FEDERATED NIDS CLIENT: {CLIENT_ID}")
print("=" * 80)
print(f"🛡️  Whitelisted IPs: {', '.join(sorted(WHITELIST_IPS))}")
print("=" * 80 + "\n")

# =====================================================
# GLOBAL STATE
# =====================================================

local_model = None

# Flow tracking
flows = {}
flow_lock = threading.Lock()

# Rate tracking
ip_rate_data = defaultdict(lambda: {
    'packets': 0, 
    'flows': 0,
    'start_time': time.time()
})
rate_lock = threading.Lock()

# Blocked IPs tracking
blocked_ips = set()
ip_threat_scores = defaultdict(int)
blocked_packet_counts = defaultdict(int)
block_lock = threading.Lock()

# Statistics
stats = {
    'packets_captured': 0,
    'packets_processed': 0,
    'packets_dropped': 0,
    'flows_tracked': 0,
    'attacks_detected': 0,
    'ml_detections': 0,
    'rate_detections': 0,
    'ips_blocked': 0,
    'normal_traffic': 0
}

running = True
server_connected = False
sio = None  # Will be initialized later

# =====================================================
# LOAD MODEL
# =====================================================

try:
    local_model = joblib.load(config.MODEL_PATH)
    print(f"✅ Model loaded: {type(local_model).__name__}")
    print(f"   Estimators: {list(local_model.named_estimators_.keys())}")
    print(f"   Weights: {list(local_model.weights)}\n")
except Exception as e:
    print(f"❌ Model load error: {e}")
    exit(1)

# =====================================================
# BLOCKED IPs PERSISTENCE
# =====================================================

def load_blocked_ips():
    """Load previously blocked IPs from file and apply firewall rules"""
    global blocked_ips, ip_threat_scores
    
    if os.path.exists(config.BLOCKED_IPS_FILE):
        try:
            with open(config.BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                blocked_ips = set(data.get('blocked_ips', []))
                threat_scores = data.get('threat_scores', {})
                ip_threat_scores = defaultdict(int, {k: v for k, v in threat_scores.items()})
            
            print(f"📥 Loaded {len(blocked_ips)} previously blocked IPs from JSON file")
            if blocked_ips:
                print(f"   Blocked: {', '.join(list(blocked_ips)[:5])}")
                if len(blocked_ips) > 5:
                    print(f"   ... and {len(blocked_ips) - 5} more")
            print()
            
            stats['ips_blocked'] = len(blocked_ips)
            
            if blocked_ips:
                print(f"🔧 Applying firewall rules for {len(blocked_ips)} IPs...")
                for ip in blocked_ips:
                    block_ip_firewall(ip)
                print(f"✅ Firewall rules applied\n")
                
        except Exception as e:
            print(f"⚠️  Error loading blocked IPs: {e}\n")
    else:
        print(f"📝 No blocked IPs file found - starting fresh\n")

def save_blocked_ips():
    """Save blocked IPs to file WITH VERIFICATION"""
    try:
        os.makedirs(os.path.dirname(config.BLOCKED_IPS_FILE), exist_ok=True)
        
        data = {
            'blocked_ips': list(blocked_ips),
            'threat_scores': dict(ip_threat_scores),
            'timestamp': datetime.now().isoformat(),
            'client_id': CLIENT_ID
        }
        
        with open(config.BLOCKED_IPS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        with open(config.BLOCKED_IPS_FILE, 'r') as f:
            verify_data = json.load(f)
        
        verify_blocked = set(verify_data.get('blocked_ips', []))
        
        if verify_blocked != blocked_ips:
            print(f"   ⚠️  WARNING: File verification failed!")
            return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Error saving blocked IPs: {e}")
        return False

def cleanup_orphaned_firewall_rules():
    """Remove firewall rules that aren't in blocked_ips.json"""
    print(f"🔧 Checking for orphaned firewall rules...")
    
    orphaned_ips = set()
    try:
        cmd = 'netsh advfirewall firewall show rule name=all'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=15)
        output = result.stdout.decode('utf-8', errors='ignore')
        
        lines = output.split('\n')
        for line in lines:
            if 'Rule Name:' in line and config.FIREWALL_RULE_PREFIX in line:
                match = re.search(r'(\d+)_(\d+)_(\d+)_(\d+)', line)
                if match:
                    ip = '.'.join(match.groups())
                    if ip not in blocked_ips and ip not in WHITELIST_IPS:
                        orphaned_ips.add(ip)
        
        if orphaned_ips:
            print(f"   ⚠️  Found {len(orphaned_ips)} orphaned firewall rules")
            for ip in orphaned_ips:
                unblock_ip_firewall(ip)
            print(f"   ✅ Cleaned up {len(orphaned_ips)} orphaned rules")
        else:
            print(f"   ✅ No orphaned rules found")
    
    except Exception as e:
        print(f"   ⚠️  Cleanup error: {e}")
    
    print()

# =====================================================
# FIREWALL FUNCTIONS
# =====================================================

def block_ip_firewall(ip_address):
    """Block IP in Windows Firewall"""
    if ip_address in WHITELIST_IPS:
        return False
    
    try:
        rule_name = f"{config.FIREWALL_RULE_PREFIX}{ip_address.replace('.', '_')}"
        
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}_IN"',
            shell=True, capture_output=True, timeout=5
        )
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"',
            shell=True, capture_output=True, timeout=5
        )
        
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address} enable=yes'
        result_in = subprocess.run(cmd_in, shell=True, capture_output=True, timeout=5)
        
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address} enable=yes'
        result_out = subprocess.run(cmd_out, shell=True, capture_output=True, timeout=5)
        
        success = result_in.returncode == 0 and result_out.returncode == 0
        
        if success:
            verify_cmd = f'netsh advfirewall firewall show rule name="{rule_name}_IN"'
            verify = subprocess.run(verify_cmd, shell=True, capture_output=True, timeout=5)
            success = verify.returncode == 0
        
        return success
        
    except Exception as e:
        return False

def unblock_ip_firewall(ip_address):
    """Remove IP block from firewall"""
    try:
        rule_name = f"{config.FIREWALL_RULE_PREFIX}{ip_address.replace('.', '_')}"
        
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}_IN"',
            shell=True, capture_output=True, timeout=5
        )
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"',
            shell=True, capture_output=True, timeout=5
        )
        
        return True
    except:
        return False

# =====================================================
# FEATURE EXTRACTION (keeping same as before)
# =====================================================

def create_flow_key(packet):
    if IP not in packet:
        return None
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    src_port = 0
    dst_port = 0
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto)
    else:
        return (dst_ip, src_ip, dst_port, src_port, proto)

def get_direction(packet, flow_key):
    src_ip = packet[IP].src
    src_port = 0
    
    if TCP in packet:
        src_port = packet[TCP].sport
    elif UDP in packet:
        src_port = packet[UDP].sport
    
    return 'fwd' if (src_ip == flow_key[0] and src_port == flow_key[2]) else 'bwd'

def extract_features(flow_data):
    features = {f: 0.0 for f in config.FEATURE_NAMES}
    
    packets = flow_data['packets']
    if not packets:
        return features
    
    features['Destination Port'] = float(flow_data.get('dst_port', 0))
    
    if len(packets) > 1:
        duration_sec = packets[-1]['timestamp'] - packets[0]['timestamp']
        features['Flow Duration'] = duration_sec * 1000000
    else:
        features['Flow Duration'] = 1.0
    
    fwd = [p for p in packets if p['direction'] == 'fwd']
    bwd = [p for p in packets if p['direction'] == 'bwd']
    
    features['Total Fwd Packets'] = float(len(fwd))
    features['Total Backward Packets'] = float(len(bwd))
    
    fwd_lens = [p['length'] for p in fwd] if fwd else [0]
    bwd_lens = [p['length'] for p in bwd] if bwd else [0]
    all_lens = [p['length'] for p in packets]
    
    features['Total Length of Fwd Packets'] = float(sum(fwd_lens))
    features['Total Length of Bwd Packets'] = float(sum(bwd_lens))
    
    features['Fwd Packet Length Mean'] = float(np.mean(fwd_lens))
    features['Bwd Packet Length Mean'] = float(np.mean(bwd_lens))
    features['Packet Length Mean'] = float(np.mean(all_lens))
    features['Packet Length Std'] = float(np.std(all_lens)) if len(all_lens) > 1 else 0.0
    
    duration_sec = features['Flow Duration'] / 1000000 if features['Flow Duration'] > 0 else 0.001
    features['Flow Packets/s'] = len(packets) / duration_sec
    features['Flow Bytes/s'] = sum(all_lens) / duration_sec
    
    if len(packets) > 1:
        timestamps = [p['timestamp'] for p in packets]
        iats = np.diff(timestamps) * 1000000
        features['Flow IAT Mean'] = float(np.mean(iats))
        features['Flow IAT Std'] = float(np.std(iats))
    
    features['SYN Flag Count'] = float(sum(1 for p in packets if p.get('syn')))
    features['ACK Flag Count'] = float(sum(1 for p in packets if p.get('ack')))
    features['RST Flag Count'] = float(sum(1 for p in packets if p.get('rst')))
    
    if fwd and 'window' in fwd[0]:
        features['Init_Win_bytes_forward'] = float(fwd[0]['window'])
    
    return features

def classify_flow(flow_key, flow_data):
    src_ip = flow_key[0]
    
    if src_ip in WHITELIST_IPS or src_ip in blocked_ips:
        return
    
    packet_count = len(flow_data['packets'])
    
    if packet_count < config.MIN_PACKETS_FOR_CLASSIFICATION:
        return
    
    if packet_count % config.CLASSIFICATION_INTERVAL != 0:
        return
    
    try:
        features = extract_features(flow_data)
        X = pd.DataFrame([features])
        
        proba = local_model.predict_proba(X)[0]
        pred = np.argmax(proba)
        conf = proba[pred]
        
        predicted_class = config.LABEL_MAP.get(pred, "Unknown")
        
        if pred in config.ATTACK_LABELS and conf >= config.CONFIDENCE_THRESHOLD:
            stats['attacks_detected'] += 1
            stats['ml_detections'] += 1
            
            print(f"\n🚨 ML ATTACK DETECTED!")
            print(f"   Type: {predicted_class}")
            print(f"   Source: {src_ip}:{flow_key[3]}")
            print(f"   Confidence: {conf*100:.1f}%")
            
            with block_lock:
                ip_threat_scores[src_ip] += 1
                score = ip_threat_scores[src_ip]
            
            if server_connected and sio:
                try:
                    sio.emit('attack_detected', {
                        'client_id': CLIENT_ID,
                        'ip_address': src_ip,
                        'attack_type': predicted_class,
                        'confidence': float(conf),
                        'threat_score': score
                    })
                except:
                    pass
            
            if score >= config.THREAT_SCORE_LIMIT and config.AUTO_BLOCK_ENABLED:
                block_ip(src_ip, predicted_class)
        else:
            stats['normal_traffic'] += 1
    
    except Exception as e:
        if config.DEBUG_MODE:
            print(f"   ⚠️  Classification error: {e}")

def check_rate_attack(src_ip):
    if not config.RATE_DETECTION_ENABLED:
        return False
    
    if src_ip in WHITELIST_IPS or src_ip in blocked_ips:
        return False
    
    with rate_lock:
        data = ip_rate_data[src_ip]
        data['packets'] += 1
        
        current_time = time.time()
        elapsed = current_time - data['start_time']
        
        if elapsed >= 1.0:
            packet_rate = data['packets'] / elapsed
            flow_rate = data['flows'] / elapsed
            
            if packet_rate > 500 or flow_rate > 50:
                stats['attacks_detected'] += 1
                stats['rate_detections'] += 1
                
                print(f"\n🚨 RATE-BASED ATTACK DETECTED!")
                print(f"   Source: {src_ip}")
                print(f"   Packet rate: {packet_rate:.0f} pkt/s")
                
                with block_lock:
                    ip_threat_scores[src_ip] += 3
                    score = ip_threat_scores[src_ip]
                
                if server_connected and sio:
                    try:
                        sio.emit('attack_detected', {
                            'client_id': CLIENT_ID,
                            'ip_address': src_ip,
                            'attack_type': "Flood Attack",
                            'confidence': 0.95,
                            'threat_score': score
                        })
                    except:
                        pass
                
                if config.AUTO_BLOCK_ENABLED:
                    block_ip(src_ip, "Flood Attack")
                
                data['packets'] = 0
                data['flows'] = 0
                data['start_time'] = current_time
                
                return True
            
            if elapsed > 5:
                data['packets'] = 0
                data['flows'] = 0
                data['start_time'] = current_time
        
        return False

def block_ip(ip_address, reason):
    if ip_address in WHITELIST_IPS:
        return
    
    with block_lock:
        if ip_address in blocked_ips:
            return
        
        print(f"\n🚫 BLOCKING IP: {ip_address}")
        print(f"   Reason: {reason}")
        
        blocked_ips.add(ip_address)
        stats['ips_blocked'] += 1
    
    if block_ip_firewall(ip_address):
        save_blocked_ips()
        
        if server_connected and sio:
            try:
                sio.emit('block_ip', {
                    'client_id': CLIENT_ID,
                    'ip_address': ip_address,
                    'reason': reason
                })
            except:
                pass

def packet_callback(packet):
    try:
        stats['packets_captured'] += 1
        
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        
        if src_ip in WHITELIST_IPS:
            return
        
        if src_ip in blocked_ips:
            stats['packets_dropped'] += 1
            with block_lock:
                blocked_packet_counts[src_ip] += 1
            return
        
        stats['packets_processed'] += 1
        
        check_rate_attack(src_ip)
        
        flow_key = create_flow_key(packet)
        if not flow_key:
            return
        
        direction = get_direction(packet, flow_key)
        
        with flow_lock:
            if flow_key not in flows:
                flows[flow_key] = {
                    'src_ip': flow_key[0],
                    'dst_ip': flow_key[1],
                    'src_port': flow_key[2],
                    'dst_port': flow_key[3],
                    'packets': [],
                    'start_time': time.time()
                }
                stats['flows_tracked'] += 1
                
                with rate_lock:
                    ip_rate_data[src_ip]['flows'] += 1
            
            flow = flows[flow_key]
            
            flow['packets'].append({
                'timestamp': time.time(),
                'length': len(packet),
                'direction': direction,
                'syn': bool(packet[TCP].flags & 0x02) if TCP in packet else False,
                'ack': bool(packet[TCP].flags & 0x10) if TCP in packet else False,
                'rst': bool(packet[TCP].flags & 0x04) if TCP in packet else False,
                'window': packet[TCP].window if TCP in packet else 0
            })
            
            classify_flow(flow_key, flow)
    
    except:
        pass

def start_capture():
    print(f"\n📡 Starting packet capture...\n")
    
    try:
        sniff(
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: not running
        )
    except PermissionError:
        print("❌ Run as Administrator!")
        exit(1)

def cleanup_flows():
    while running:
        time.sleep(30)
        with flow_lock:
            now = time.time()
            old = [k for k, v in flows.items() if now - v['start_time'] > config.FLOW_TIMEOUT]
            for k in old:
                del flows[k]

def report_stats():
    while running:
        time.sleep(5)
        if server_connected and sio:
            try:
                sio.emit('stats_update', {'client_id': CLIENT_ID, 'stats': stats})
            except:
                pass

def display_status():
    while running:
        time.sleep(3)
        print(f"\n📊 STATUS - {datetime.now().strftime('%H:%M:%S')}")
        print(f"   Captured: {stats['packets_captured']} | Processed: {stats['packets_processed']} | Dropped: {stats['packets_dropped']}")
        print(f"   Flows: {len(flows)} | Attacks: {stats['attacks_detected']} (ML: {stats['ml_detections']}, Rate: {stats['rate_detections']})")
        print(f"   Blocked IPs: {stats['ips_blocked']} | Normal: {stats['normal_traffic']}")
        
        with block_lock:
            if blocked_ips:
                print(f"\n   🚫 BLOCKED IPs:")
                for ip in list(blocked_ips):
                    dropped = blocked_packet_counts.get(ip, 0)
                    print(f"      {ip} - {dropped} packets dropped")
            else:
                print(f"\n   ✅ No IPs currently blocked")
        print()

def command_listener():
    global running
    
    print("\n" + "="*60)
    print("💡 COMMANDS:")
    print("   'list' or 'l'        - Show blocked IPs")
    print("   'unblock <IP>'       - Unblock specific IP")
    print("   'unblock all'        - Unblock all IPs")
    print("   'quit' or 'q'        - Exit program")
    print("="*60 + "\n")
    
    while running:
        try:
            cmd = input().strip().lower()
            
            if cmd in ['list', 'l']:
                if blocked_ips:
                    print(f"\n🚫 Blocked IPs ({len(blocked_ips)}):")
                    for ip in sorted(blocked_ips):
                        print(f"   {ip}")
                else:
                    print(f"\n✅ No blocked IPs")
                print()
            
            elif cmd.startswith('unblock '):
                parts = cmd.split()
                if len(parts) == 2:
                    if parts[1] == 'all':
                        for ip in list(blocked_ips):
                            with block_lock:
                                if ip in blocked_ips:
                                    blocked_ips.remove(ip)
                                    stats['ips_blocked'] -= 1
                            unblock_ip_firewall(ip)
                        save_blocked_ips()
                    else:
                        if parts[1] in blocked_ips:
                            with block_lock:
                                blocked_ips.remove(parts[1])
                                stats['ips_blocked'] -= 1
                            unblock_ip_firewall(parts[1])
                            save_blocked_ips()
            
            elif cmd in ['quit', 'q']:
                running = False
                break
        
        except (EOFError, KeyboardInterrupt):
            break

# =====================================================
# SOCKET.IO CONNECTION - COMPLETELY REWRITTEN
# =====================================================

def setup_socketio():
    """Setup Socket.IO with proper event handlers"""
    global sio, server_connected
    
    # Create new Socket.IO client
    sio = socketio.Client(
        reconnection=True,
        reconnection_attempts=5,
        reconnection_delay=2,
        logger=False,
        engineio_logger=False
    )
    
    @sio.event
    def connect():
        global server_connected
        server_connected = True
        print(f"\n✅ Connected to server!")
        
        # Register immediately
        try:
            client_ip = socket.gethostbyname(socket.gethostname())
        except:
            client_ip = '127.0.0.1'
        
        print(f"📤 Registering as {CLIENT_ID}...")
        sio.emit('register_client', {
            'client_id': CLIENT_ID,
            'client_ip': client_ip
        })
    
    @sio.event
    def disconnect():
        global server_connected
        server_connected = False
        print(f"\n❌ Disconnected from server")
    
    @sio.on('initial_sync')
    def on_sync(data):
        print(f"✅ Server confirmed registration!\n")
    
    @sio.on('sync_block_ip')
    def on_block(data):
        ip = data.get('ip_address')
        if ip and ip not in blocked_ips:
            with block_lock:
                blocked_ips.add(ip)
                stats['ips_blocked'] += 1
            block_ip_firewall(ip)
            save_blocked_ips()
    
    @sio.on('sync_unblock_ip')
    def on_unblock(data):
        ip = data.get('ip_address')
        if ip and ip in blocked_ips:
            with block_lock:
                blocked_ips.remove(ip)
                stats['ips_blocked'] -= 1
            unblock_ip_firewall(ip)
            save_blocked_ips()
    
    return sio

# =====================================================
# MAIN
# =====================================================

def main():
    global sio, server_connected
    
    load_blocked_ips()
    cleanup_orphaned_firewall_rules()
    
    # Setup Socket.IO
    sio = setup_socketio()
    
    # Connect to server
    print(f"🔄 Connecting to server {config.SERVER_HOST}:{config.SERVER_PORT}...")
    try:
        sio.connect(f"http://{config.SERVER_HOST}:{config.SERVER_PORT}")
        time.sleep(2)
    except Exception as e:
        print(f"⚠️  Could not connect: {e}")
        print(f"⚠️  Running OFFLINE\n")
    
    # Start threads
    threading.Thread(target=cleanup_flows, daemon=True).start()
    threading.Thread(target=report_stats, daemon=True).start()
    threading.Thread(target=display_status, daemon=True).start()
    threading.Thread(target=command_listener, daemon=True).start()
    
    try:
        start_capture()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
    finally:
        save_blocked_ips()
        if server_connected and sio:
            sio.disconnect()

if __name__ == '__main__':
    print("\n⚠️  IMPORTANT: Run as Administrator!\n")
    input("Press Enter to start...")
    main()
