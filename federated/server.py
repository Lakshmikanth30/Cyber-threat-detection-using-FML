"""
FEDERATED NIDS - SERVER (FIXED: attack tracking + dashboard API endpoints)
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import joblib
import json
import os
import time
from datetime import datetime
from collections import defaultdict, deque
import config

app = Flask(__name__, template_folder='../dashboard/templates',
            static_folder='../dashboard/static')
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    ping_timeout=120,
    ping_interval=25,
    logger=False,
    engineio_logger=False
)

# =====================================================
# GLOBAL STATE
# =====================================================

clients = {}
global_blocked_ips = set()
pending_updates = {}
training_history = []
global_model = None
federated_rounds = 0

# FIX 1: track attack counts per type for the doughnut chart
attack_types_counter = defaultdict(int)

# FIX 2: store recent attacks for the timeline + feed
recent_attacks = deque(maxlen=200)   # newest first

global_stats = {
    'total_attacks_detected': 0,
    'total_ips_blocked': 0,
    'total_packets_processed': 0,
    'clients_connected': 0,
    'global_accuracy': 0.9967,
    'attack_types': {
        'BruteForce': 0,
        'DoS/DDoS': 0,
        'PortScan': 0,
    }
}

print("=" * 80)
print("🌐 FEDERATED NIDS - GLOBAL SERVER")
print("=" * 80)
print(f"Server: {config.SERVER_HOST}:{config.SERVER_PORT}")
print(f"Confidence Threshold: {config.CONFIDENCE_THRESHOLD*100}%")
print(f"Auto-blocking: {'ENABLED' if config.AUTO_BLOCK_ENABLED else 'DISABLED'}")
print("=" * 80 + "\n")

# =====================================================
# LOAD GLOBAL MODEL
# =====================================================

try:
    global_model = joblib.load(config.MODEL_PATH)
    print(f"✅ Global model loaded: {config.MODEL_PATH}\n")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit(1)

# Load existing blocked IPs
if os.path.exists(config.BLOCKED_IPS_FILE):
    try:
        with open(config.BLOCKED_IPS_FILE, 'r') as f:
            data = json.load(f)
            global_blocked_ips = set(data.get('blocked_ips', []))
        print(f"📥 Loaded {len(global_blocked_ips)} previously blocked IPs\n")
        global_stats['total_ips_blocked'] = len(global_blocked_ips)
    except Exception:
        pass

# =====================================================
# HELPER FUNCTIONS
# =====================================================

def save_blocked_ips():
    try:
        os.makedirs(os.path.dirname(config.BLOCKED_IPS_FILE), exist_ok=True)
        with open(config.BLOCKED_IPS_FILE, 'w') as f:
            json.dump({
                'blocked_ips': list(global_blocked_ips),
                'timestamp': datetime.now().isoformat(),
                'total_blocked': len(global_blocked_ips)
            }, f, indent=2)
    except Exception as e:
        print(f"❌ Error saving blocked IPs: {e}")


def log_event(event_type, message, client_id=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_str = f"[{client_id}]" if client_id else "[SERVER]"
    log_line = f"{timestamp} {client_str} {event_type}: {message}"
    print(log_line)
    try:
        with open(config.LOG_FILE, 'a') as f:
            f.write(log_line + "\n")
    except Exception:
        pass


def broadcast_to_all_clients(event_name, data):
    print(f"\n🔊 Broadcasting '{event_name}' to {len(clients)} clients")
    success_count = 0
    for client_id, client_data in list(clients.items()):
        try:
            socket_id = client_data['socket_id']
            socketio.emit(event_name, data, room=socket_id)
            print(f"   ✅ Sent to {client_id} (socket: {socket_id})")
            success_count += 1
        except Exception as e:
            print(f"   ❌ Failed to send to {client_id}: {e}")
    print(f"   📊 Successfully sent to {success_count}/{len(clients)} clients\n")
    return success_count

# =====================================================
# WEBSOCKET EVENTS
# =====================================================

@socketio.on('connect')
def handle_connect():
    socket_id = request.sid
    log_event("CONNECT", f"New client socket: {socket_id}")
    emit('server_ready', {
        'server_time': datetime.now().isoformat(),
        'global_blocked_ips': list(global_blocked_ips),
        'confidence_threshold': config.CONFIDENCE_THRESHOLD
    })


@socketio.on('disconnect')
def handle_disconnect():
    socket_id = request.sid
    client_id = None
    for cid, cdata in list(clients.items()):
        if cdata['socket_id'] == socket_id:
            client_id = cid
            del clients[cid]
            break
    if client_id:
        log_event("DISCONNECT", "Client offline", client_id)
        global_stats['clients_connected'] = len(clients)
        print(f"📊 Connected clients: {len(clients)}\n")


@socketio.on('register_client')
def handle_register(data):
    client_id = data.get('client_id')
    client_ip  = data.get('client_ip')
    socket_id  = request.sid

    clients[client_id] = {
        'socket_id': socket_id,
        'client_ip': client_ip,
        'last_seen': time.time(),
        'stats': {
            'attacks_detected': 0,
            'ips_blocked': 0,
            'packets_processed': 0
        }
    }
    global_stats['clients_connected'] = len(clients)
    log_event("REGISTER", f"Client registered from {client_ip}", client_id)
    print(f"📊 Connected clients: {len(clients)}")
    print(f"   Active: {', '.join(clients.keys())}\n")

    emit('initial_sync', {
        'global_blocked_ips': list(global_blocked_ips),
        'global_stats': global_stats
    })

# =====================================================
# ATTACK DETECTION  ← FIX: store + emit alert
# =====================================================

@socketio.on('attack_detected')
def handle_attack_detected(data):
    """Client detected an attack — store it and push to dashboard."""
    client_id   = data.get('client_id', 'unknown')
    ip_address  = data.get('ip_address', '?')
    attack_type = data.get('attack_type', 'Unknown')
    confidence  = data.get('confidence', 0)
    threat_score = data.get('threat_score', 0)

    # Update per-client stats
    if client_id in clients:
        clients[client_id]['stats']['attacks_detected'] += 1

    # Update global counters
    global_stats['total_attacks_detected'] += 1

    # FIX: increment per-type counter for doughnut chart
    known_types = ('BruteForce', 'DoS/DDoS', 'PortScan')
    for t in known_types:
        if t.lower() in attack_type.lower() or attack_type == t:
            global_stats['attack_types'][t] = global_stats['attack_types'].get(t, 0) + 1
            break
    else:
        # Catch-all bucket so unknown labels don't vanish silently
        global_stats['attack_types'][attack_type] = global_stats['attack_types'].get(attack_type, 0) + 1

    # FIX: store in recent_attacks deque for the feed / timeline API
    record = {
        'timestamp':    datetime.now().isoformat(),
        'client_id':    client_id,
        'ip_address':   ip_address,
        'attack_type':  attack_type,
        'confidence':   float(confidence),
        'threat_score': int(threat_score),
    }
    recent_attacks.appendleft(record)

    log_event("ATTACK", f"{attack_type} from {ip_address} ({confidence:.1%}) Score:{threat_score}", client_id)

    # FIX: push live alert to dashboard via 'attack_alert' event
    socketio.emit('attack_alert', record)


@socketio.on('stats_update')
def handle_stats_update(data):
    client_id = data.get('client_id')
    stats_in  = data.get('stats', {})

    if client_id in clients:
        # merge incoming stats
        for k, v in stats_in.items():
            clients[client_id]['stats'][k] = v
        clients[client_id]['last_seen'] = time.time()

        global_stats['total_packets_processed'] = sum(
            c['stats'].get('packets_processed', 0) for c in clients.values()
        )
        global_stats['total_ips_blocked'] = sum(
            c['stats'].get('ips_blocked', 0) for c in clients.values()
        )

# =====================================================
# IP BLOCKING SYNCHRONIZATION
# =====================================================

@socketio.on('block_ip')
def handle_block_ip(data):
    ip_address = data.get('ip_address')
    reason     = data.get('reason', 'Unknown')
    client_id  = data.get('client_id')

    if not ip_address:
        return

    print(f"\n{'='*60}\n🚫 BLOCK REQUEST from {client_id}  IP: {ip_address}")

    if ip_address not in global_blocked_ips:
        global_blocked_ips.add(ip_address)
        save_blocked_ips()
        global_stats['total_ips_blocked'] = len(global_blocked_ips)
        log_event("BLOCK_IP", f"{ip_address} - Reason: {reason}", client_id)

        sync_data = {
            'ip_address': ip_address,
            'reason':     reason,
            'blocked_by': client_id,
            'timestamp':  datetime.now().isoformat()
        }
        broadcast_to_all_clients('sync_block_ip', sync_data)
        print(f"✅ BLOCK SYNCED: {ip_address}  Total: {len(global_blocked_ips)}\n{'='*60}\n")
    else:
        print(f"   ℹ️  Already blocked globally\n{'='*60}\n")


@socketio.on('unblock_ip')
def handle_unblock_ip(data):
    ip_address = data.get('ip_address')
    client_id  = data.get('client_id')

    print(f"\n{'='*60}\n🔓 UNBLOCK REQUEST from {client_id}  IP: {ip_address}")

    if ip_address in global_blocked_ips:
        global_blocked_ips.remove(ip_address)
        save_blocked_ips()
        global_stats['total_ips_blocked'] = len(global_blocked_ips)
        log_event("UNBLOCK_IP", f"{ip_address}", client_id)

        sync_data = {
            'ip_address':   ip_address,
            'unblocked_by': client_id,
            'timestamp':    datetime.now().isoformat()
        }
        broadcast_to_all_clients('sync_unblock_ip', sync_data)
        print(f"✅ UNBLOCK SYNCED: {ip_address}  Total: {len(global_blocked_ips)}\n{'='*60}\n")
    else:
        print(f"   ℹ️  Not in global blocked list\n{'='*60}\n")

# =====================================================
# FEDERATED LEARNING
# =====================================================

@socketio.on('model_update')
def handle_model_update(data):
    global federated_rounds
    client_id   = data.get('client_id')
    num_samples = data.get('num_samples', 0)
    accuracy    = data.get('accuracy', 0)

    pending_updates[client_id] = {
        'num_samples': num_samples,
        'accuracy':    accuracy,
        'timestamp':   time.time()
    }
    log_event("MODEL_UPDATE", f"{num_samples} samples, {accuracy:.2%} accuracy", client_id)

    if len(pending_updates) >= 2:
        aggregate_models()


def aggregate_models():
    global pending_updates, federated_rounds
    if len(pending_updates) < 2:
        return

    log_event("AGGREGATE", f"Aggregating {len(pending_updates)} client models")

    total_samples = sum(u['num_samples'] for u in pending_updates.values())
    weighted_acc  = (sum(u['num_samples'] * u['accuracy'] for u in pending_updates.values())
                     / total_samples) if total_samples > 0 else 0

    federated_rounds += 1
    global_stats['global_accuracy'] = weighted_acc

    training_history.append({
        'timestamp':     datetime.now().isoformat(),
        'round':         federated_rounds,
        'num_clients':   len(pending_updates),
        'total_samples': total_samples,
        'global_accuracy': weighted_acc
    })

    print(f"📊 Global model updated (round {federated_rounds}): {weighted_acc:.2%} accuracy ({total_samples} samples)\n")
    pending_updates.clear()

    socketio.emit('global_model_ready', {
        'round':    federated_rounds,
        'accuracy': weighted_acc,
        'timestamp': datetime.now().isoformat()
    }, broadcast=True)

# =====================================================
# REST API ENDPOINTS  ← FIX: add all endpoints dashboard needs
# =====================================================

@app.route('/')
def index():
    """Serve the dashboard HTML."""
    from flask import render_template
    return render_template('dashboard.html')


@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        'status':             'running',
        'clients_connected':  len(clients),
        'federated_rounds':   federated_rounds,
        'global_stats':       global_stats,
        'blocked_ips_count':  len(global_blocked_ips),
        'timestamp':          datetime.now().isoformat()
    })


@app.route('/api/clients', methods=['GET'])
def api_clients():
    return jsonify({
        'clients': {
            cid: {
                'client_ip':  cdata['client_ip'],
                'socket_id':  cdata['socket_id'],
                'stats':      cdata['stats'],
                'last_seen':  cdata['last_seen']
            }
            for cid, cdata in clients.items()
        },
        'count': len(clients)
    })


@app.route('/api/blocked_ips', methods=['GET'])
def api_blocked_ips():
    return jsonify({
        'blocked_ips': sorted(list(global_blocked_ips)),
        'count':        len(global_blocked_ips)
    })


@app.route('/api/attacks/recent', methods=['GET'])
def api_recent_attacks():
    """Return recent attacks list for the feed and timeline chart."""
    return jsonify({
        'attacks': list(recent_attacks),   # already newest-first
        'count':   len(recent_attacks)
    })


@app.route('/api/history', methods=['GET'])
def api_history():
    return jsonify(training_history)


# Legacy URL aliases so old bookmarks still work
@app.route('/status',      methods=['GET'])
def get_status():      return api_status()

@app.route('/blocked_ips', methods=['GET'])
def get_blocked_ips(): return api_blocked_ips()

@app.route('/clients',     methods=['GET'])
def get_clients():     return api_clients()

@app.route('/history',     methods=['GET'])
def get_history():     return api_history()

# =====================================================
# START SERVER
# =====================================================

if __name__ == '__main__':
    os.makedirs(os.path.dirname(config.LOG_FILE),       exist_ok=True)
    os.makedirs(os.path.dirname(config.BLOCKED_IPS_FILE), exist_ok=True)

    print("\n🚀 Starting Federated NIDS Server...")
    print(f"   Dashboard  : http://{config.SERVER_HOST}:{config.SERVER_PORT}/")
    print(f"   Status API : http://{config.SERVER_HOST}:{config.SERVER_PORT}/api/status")
    print(f"   Blocked IPs: http://{config.SERVER_HOST}:{config.SERVER_PORT}/api/blocked_ips")
    print("\n⏳ Waiting for clients to connect...\n")

    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=config.SERVER_PORT,
            debug=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n\n👋 Server shutting down...")
        save_blocked_ips()
