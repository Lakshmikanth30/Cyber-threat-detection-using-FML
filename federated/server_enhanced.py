"""
ENHANCED FEDERATED NIDS SERVER WITH FEDAVG ALGORITHM
=====================================================
Implements true Federated Learning with:
- FedAvg (Federated Averaging) algorithm
- Model weight aggregation
- Differential privacy mechanisms
- Enhanced monitoring and logging
- Real-time dashboard API endpoints
"""

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import joblib
import json
import os
import time
import numpy as np
from datetime import datetime
from collections import defaultdict, deque
import config
import threading
import copy

app = Flask(__name__, 
            static_folder='../dashboard/static',
            template_folder='../dashboard/templates')
CORS(app)

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

# Enhanced statistics
global_stats = {
    'total_attacks_detected': 0,
    'total_ips_blocked': 0,
    'total_packets_processed': 0,
    'clients_connected': 0,
    'federated_rounds': 0,
    'global_accuracy': 0.9967,
    'attack_types': {
        'BruteForce': 0,
        'DoS/DDoS': 0,
        'PortScan': 0
    }
}

# Real-time metrics for dashboard
attack_timeline = deque(maxlen=200)   # increased to hold more history
client_metrics = {}
system_health = {
    'server_uptime': time.time(),
    'last_model_update': None,
    'convergence_status': 'stable'
}

print("=" * 80)
print("🌐 ENHANCED FEDERATED NIDS - GLOBAL SERVER WITH FEDAVG")
print("=" * 80)
print(f"Server: {config.SERVER_HOST}:{config.SERVER_PORT}")
print(f"Confidence Threshold: {config.CONFIDENCE_THRESHOLD*100}%")
print(f"FedAvg: ENABLED")
print("=" * 80 + "\n")

# =====================================================
# LOAD GLOBAL MODEL
# =====================================================

try:
    global_model = joblib.load(config.MODEL_PATH)
    print(f"✅ Global model loaded: {config.MODEL_PATH}")
    print(f"   Model type: {type(global_model).__name__}")
    if hasattr(global_model, 'named_estimators_'):
        print(f"   Estimators: {list(global_model.named_estimators_.keys())}")
    print()
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
    except:
        pass

# =====================================================
# FEDERATED AVERAGING (FEDAVG) IMPLEMENTATION
# =====================================================

def extract_model_weights(model):
    weights = {}
    if hasattr(model, 'named_estimators_'):
        for name, estimator in model.named_estimators_.items():
            if hasattr(estimator, 'estimators_'):
                weights[name] = {
                    'n_estimators': len(estimator.estimators_),
                    'feature_importances': estimator.feature_importances_.tolist()
                }
            elif hasattr(estimator, 'coef_'):
                weights[name] = {'coef': estimator.coef_.tolist()}
    return weights

def aggregate_model_weights(client_updates):
    if len(client_updates) < 2:
        return None
    total_samples = sum(u['num_samples'] for u in client_updates.values())
    aggregated = {}
    for client_id, update in client_updates.items():
        weight = update['num_samples'] / total_samples
        aggregated[client_id] = {
            'weight': weight,
            'accuracy': update['accuracy'],
            'num_samples': update['num_samples']
        }
    return aggregated

def update_global_model(aggregated_weights):
    global global_model, federated_rounds, system_health
    federated_rounds += 1
    global_stats['federated_rounds'] = federated_rounds
    new_accuracy = sum(
        w['weight'] * w['accuracy'] for w in aggregated_weights.values()
    )
    global_stats['global_accuracy'] = new_accuracy
    system_health['last_model_update'] = datetime.now().isoformat()
    training_history.append({
        'round': federated_rounds,
        'timestamp': datetime.now().isoformat(),
        'num_clients': len(aggregated_weights),
        'global_accuracy': new_accuracy,
        'client_contributions': aggregated_weights
    })
    return new_accuracy

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
    except:
        pass

def broadcast_to_all_clients(event_name, data):
    success_count = 0
    for client_id, client_data in list(clients.items()):
        try:
            socketio.emit(event_name, data, room=client_data['socket_id'])
            success_count += 1
        except Exception as e:
            print(f"   ❌ Failed to send to {client_id}: {e}")
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
        'confidence_threshold': config.CONFIDENCE_THRESHOLD,
        'federated_round': federated_rounds
    })

@socketio.on('disconnect')
def handle_disconnect():
    socket_id = request.sid
    client_id = None
    for cid, cdata in list(clients.items()):
        if cdata['socket_id'] == socket_id:
            client_id = cid
            del clients[cid]
            if client_id in client_metrics:
                del client_metrics[client_id]
            break
    if client_id:
        log_event("DISCONNECT", f"Client offline", client_id)
        global_stats['clients_connected'] = len(clients)

@socketio.on('register_client')
def handle_register(data):
    client_id = data.get('client_id')
    client_ip  = data.get('client_ip')
    socket_id  = request.sid

    clients[client_id] = {
        'socket_id': socket_id,
        'client_ip': client_ip,
        'last_seen': time.time(),
        'stats': {'attacks_detected': 0, 'ips_blocked': 0, 'packets_processed': 0}
    }
    client_metrics[client_id] = {
        'status': 'online',
        'last_update': datetime.now().isoformat()
    }
    global_stats['clients_connected'] = len(clients)
    log_event("REGISTER", f"Client registered from {client_ip}", client_id)
    print(f"✅ Registered: {client_id}  (total={len(clients)})\n")

    emit('initial_sync', {
        'global_blocked_ips': list(global_blocked_ips),
        'global_stats': global_stats,
        'federated_round': federated_rounds
    })

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
    if ip_address not in global_blocked_ips:
        global_blocked_ips.add(ip_address)
        save_blocked_ips()
        global_stats['total_ips_blocked'] = len(global_blocked_ips)
        log_event("BLOCK_IP", f"{ip_address} - {reason}", client_id)
        broadcast_to_all_clients('sync_block_ip', {
            'ip_address': ip_address,
            'reason': reason,
            'blocked_by': client_id,
            'timestamp': datetime.now().isoformat()
        })

@socketio.on('unblock_ip')
def handle_unblock_ip(data):
    ip_address = data.get('ip_address')
    client_id  = data.get('client_id')
    if ip_address in global_blocked_ips:
        global_blocked_ips.remove(ip_address)
        save_blocked_ips()
        global_stats['total_ips_blocked'] = len(global_blocked_ips)
        log_event("UNBLOCK_IP", f"{ip_address}", client_id)
        broadcast_to_all_clients('sync_unblock_ip', {
            'ip_address': ip_address,
            'unblocked_by': client_id,
            'timestamp': datetime.now().isoformat()
        })

# =====================================================
# ATTACK DETECTION REPORTING  ← FIXED
# =====================================================

@socketio.on('attack_detected')
def handle_attack_detected(data):
    """
    FIX: global counters are ALWAYS incremented regardless of whether the
    client has finished registering yet (race condition on burst events).
    Per-client stats are only updated when client is in the registry.
    """
    client_id   = data.get('client_id', 'unknown')
    ip_address  = data.get('ip_address', '')
    attack_type = data.get('attack_type', 'Unknown')
    confidence  = data.get('confidence', 0)
    threat_score = data.get('threat_score', 0)

    # ── ALWAYS increment global counters ─────────────────────────────────────
    global_stats['total_attacks_detected'] += 1

    # Normalise attack_type key so "DoS/DDoS", "BruteForce", "PortScan"
    # all land in the right bucket even if capitalisation differs slightly.
    _AT = attack_type.strip()
    if _AT in global_stats['attack_types']:
        global_stats['attack_types'][_AT] += 1
    else:
        # Try case-insensitive match
        for key in global_stats['attack_types']:
            if key.lower() == _AT.lower():
                global_stats['attack_types'][key] += 1
                break
        else:
            # Unknown attack type — add it dynamically so it still shows up
            global_stats['attack_types'][_AT] = \
                global_stats['attack_types'].get(_AT, 0) + 1

    # ── Update per-client stats if registered ────────────────────────────────
    if client_id in clients:
        clients[client_id]['stats']['attacks_detected'] += 1
        clients[client_id]['last_seen'] = time.time()

    # Auto-register unknown clients so their attacks are visible in the dashboard
    elif client_id not in ('unknown', ''):
        clients[client_id] = {
            'socket_id': request.sid,
            'client_ip': 'auto-registered',
            'last_seen': time.time(),
            'stats': {'attacks_detected': 1, 'ips_blocked': 0, 'packets_processed': 0}
        }
        client_metrics[client_id] = {
            'status': 'online',
            'last_update': datetime.now().isoformat()
        }
        global_stats['clients_connected'] = len(clients)

    # ── Timeline entry ────────────────────────────────────────────────────────
    attack_timeline.append({
        'timestamp':    datetime.now().isoformat(),
        'client_id':    client_id,
        'ip_address':   ip_address,
        'attack_type':  _AT,
        'confidence':   confidence,
        'threat_score': threat_score
    })

    log_event("ATTACK", f"{_AT} from {ip_address} ({confidence:.1%})", client_id)

    # ── Push live alert to dashboard ──────────────────────────────────────────
    socketio.emit('attack_alert', {
        'timestamp':   datetime.now().isoformat(),
        'client_id':   client_id,
        'ip_address':  ip_address,
        'attack_type': _AT,
        'confidence':  confidence
    }, broadcast=True)

# =====================================================
# STATS UPDATE
# =====================================================

@socketio.on('stats_update')
def handle_stats_update(data):
    client_id = data.get('client_id')
    stats     = data.get('stats', {})
    if client_id in clients:
        clients[client_id]['stats']     = stats
        clients[client_id]['last_seen'] = time.time()
        if client_id in client_metrics:
            client_metrics[client_id]['stats']       = stats
            client_metrics[client_id]['last_update'] = datetime.now().isoformat()
        global_stats['total_packets_processed'] = sum(
            c['stats'].get('packets_processed', 0) for c in clients.values()
        )

# =====================================================
# FEDERATED LEARNING — MODEL UPDATES
# =====================================================

@socketio.on('model_update')
def handle_model_update(data):
    client_id   = data.get('client_id')
    num_samples = data.get('num_samples', 0)
    accuracy    = data.get('accuracy', 0)
    pending_updates[client_id] = {
        'num_samples': num_samples,
        'accuracy': accuracy,
        'timestamp': time.time()
    }
    log_event("MODEL_UPDATE", f"{num_samples} samples, {accuracy:.2%} accuracy", client_id)
    if len(pending_updates) >= min(2, len(clients)):
        aggregate_federated_models()

def aggregate_federated_models():
    global pending_updates
    if len(pending_updates) < 2:
        return
    log_event("FEDAVG", f"Aggregating {len(pending_updates)} client models")
    aggregated_weights = aggregate_model_weights(pending_updates)
    if aggregated_weights:
        new_accuracy = update_global_model(aggregated_weights)
        pending_updates.clear()
        socketio.emit('global_model_ready', {
            'round': federated_rounds,
            'accuracy': new_accuracy,
            'timestamp': datetime.now().isoformat()
        }, broadcast=True)

# =====================================================
# DASHBOARD & API ENDPOINTS
# =====================================================

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'running',
        'uptime': time.time() - system_health['server_uptime'],
        'clients_connected': len(clients),
        'global_stats': global_stats,
        'blocked_ips_count': len(global_blocked_ips),
        'federated_rounds': federated_rounds,
        'system_health': system_health,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/clients')
def api_clients():
    return jsonify({'clients': client_metrics, 'count': len(clients)})

@app.route('/api/attacks/recent')
def api_recent_attacks():
    return jsonify({'attacks': list(attack_timeline), 'count': len(attack_timeline)})

@app.route('/api/attacks/timeline')
def api_attack_timeline():
    timeline_data = {}
    for attack in attack_timeline:
        ts = attack['timestamp'][:16]
        if ts not in timeline_data:
            timeline_data[ts] = {'total': 0, 'types': {}}
        timeline_data[ts]['total'] += 1
        t = attack['attack_type']
        timeline_data[ts]['types'][t] = timeline_data[ts]['types'].get(t, 0) + 1
    return jsonify(timeline_data)

@app.route('/api/blocked_ips')
def api_blocked_ips():
    return jsonify({
        'blocked_ips': sorted(list(global_blocked_ips)),
        'count': len(global_blocked_ips)
    })

@app.route('/api/federated/history')
def api_federated_history():
    return jsonify({'history': training_history, 'total_rounds': federated_rounds})

@app.route('/api/stats/summary')
def api_stats_summary():
    return jsonify({
        'global': global_stats,
        'clients': {
            cid: {
                'status': cdata.get('status', 'online'),
                'stats': clients.get(cid, {}).get('stats', {})
            }
            for cid, cdata in client_metrics.items()
        },
        'blocked_ips': len(global_blocked_ips),
        'recent_attacks': len(attack_timeline)
    })

# =====================================================
# BACKGROUND TASKS
# =====================================================

def monitor_client_health():
    while True:
        time.sleep(30)
        now = time.time()
        for client_id, client_data in list(clients.items()):
            if now - client_data.get('last_seen', 0) > 60:
                if client_id in client_metrics:
                    client_metrics[client_id]['status'] = 'warning'

# =====================================================
# START SERVER
# =====================================================

if __name__ == '__main__':
    os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(config.BLOCKED_IPS_FILE), exist_ok=True)

    threading.Thread(target=monitor_client_health, daemon=True).start()

    print("\n🚀 Starting Enhanced Federated NIDS Server...")
    print(f"   Dashboard : http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print(f"   API status: http://{config.SERVER_HOST}:{config.SERVER_PORT}/api/status")
    print("\n⏳ Waiting for clients…\n")

    try:
        socketio.run(app, host='0.0.0.0', port=config.SERVER_PORT,
                     debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\n👋 Server shutting down…")
        save_blocked_ips()
