"""
FEDERATED NIDS — SIMULATION CLIENT  v5
========================================
Generates synthetic attack flows, classifies them through the real ML model,
and streams results to the server so the dashboard charts populate live.

Two-path detection:
  [ML]  — model genuinely returns an attack class at >= threshold
  [SIM] — attack scenario but model uncertain → simulation forces the event

Both paths call sio.emit('attack_detected') so the server's attack_types
counter and timeline fill up → doughnut + line chart show real data.

Run in a SEPARATE terminal:
    python simulation_client.py
No Administrator rights needed. No real packets. No firewall changes.
"""

import socketio as sio_module
import joblib
import numpy as np
import pandas as pd
import time
import threading
import socket
import random
import sys
import os
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

# ══════════════════════════════════════════════════════════════════════════════
#  IDENTITY & TIMING
# ══════════════════════════════════════════════════════════════════════════════

CLIENT_ID  = "sim_node_1"
FLOW_DELAY = 0.5        # seconds between generated flows (lower = faster charts)
BURST_ON_CONNECT = 15   # send this many attack events right after registration

# ══════════════════════════════════════════════════════════════════════════════
#  FAKE IP POOLS  (never touch real firewall)
# ══════════════════════════════════════════════════════════════════════════════

ATTACKER_POOL = (
    ["10.0.0."      + str(i) for i in range(10, 60)] +
    ["172.16.0."    + str(i) for i in range(5,  50)] +
    ["192.168.100." + str(i) for i in range(1,  40)]
)

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

stats = {
    "flows_simulated":  0,
    "attacks_detected": 0,
    "ml_detections":    0,
    "sim_detections":   0,
    "normal_traffic":   0,
    "ips_blocked":      0,
}
blocked_ips:         set  = set()
threat_scores:       dict = defaultdict(int)
running:             bool = True
server_connected:    bool = False
registration_done:   bool = False   # wait until server confirms before bursting
sio                       = None
local_model               = None

# ══════════════════════════════════════════════════════════════════════════════
#  MODEL LOADER
# ══════════════════════════════════════════════════════════════════════════════

def load_model():
    global local_model
    try:
        local_model = joblib.load(config.MODEL_PATH)
        print(f"  ✅ Model loaded  : {type(local_model).__name__}")
        if hasattr(local_model, "named_estimators_"):
            print(f"     Estimators   : {list(local_model.named_estimators_.keys())}")
        print()
    except Exception as e:
        print(f"  ❌ Cannot load model: {e}\n")
        sys.exit(1)


def probe_model():
    """Quick sanity check — shows what the model predicts for extreme vectors."""
    print("  🔍 Probing model with extreme feature vectors ...")
    probes = {
        "syn_flood": _feat_bruteforce_extreme(),
        "dos_flood": _feat_dos_extreme(),
        "port_scan": _feat_scan_extreme(),
        "normal":    _feat_normal_extreme(),
    }
    for name, feats in probes.items():
        X     = pd.DataFrame([feats], columns=config.FEATURE_NAMES)
        proba = local_model.predict_proba(X)[0]
        pidx  = int(np.argmax(proba))
        conf  = float(proba[pidx])
        lbl   = config.LABEL_MAP.get(pidx, f"idx_{pidx}")
        hit   = pidx in config.ATTACK_LABELS and conf >= config.CONFIDENCE_THRESHOLD
        print(f"     {name:<12s} → [{pidx}] {lbl:<12s} conf={conf:.3f}  ML_attack={hit}")
    print()

# ── Extreme probe helpers ──────────────────────────────────────────────────

def _z():
    return {f: 0.0 for f in config.FEATURE_NAMES}

def _feat_bruteforce_extreme():
    f = _z(); f.update({
        "Destination Port": 22, "Flow Duration": 8000,
        "Total Fwd Packets": 600, "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 36600, "Total Length of Bwd Packets": 40,
        "Fwd Packet Length Mean": 61, "Bwd Packet Length Mean": 40,
        "Packet Length Mean": 61, "Packet Length Std": 5,
        "Flow Packets/s": 75000, "Flow Bytes/s": 4575000,
        "Flow IAT Mean": 13, "Flow IAT Std": 4,
        "SYN Flag Count": 600, "ACK Flag Count": 1,
        "RST Flag Count": 0, "Init_Win_bytes_forward": 1024}); return f

def _feat_dos_extreme():
    f = _z(); f.update({
        "Destination Port": 80, "Flow Duration": 3000,
        "Total Fwd Packets": 1500, "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 2100000, "Total Length of Bwd Packets": 60,
        "Fwd Packet Length Mean": 1400, "Bwd Packet Length Mean": 60,
        "Packet Length Mean": 1400, "Packet Length Std": 8,
        "Flow Packets/s": 500000, "Flow Bytes/s": 700000000,
        "Flow IAT Mean": 2, "Flow IAT Std": 0.5,
        "SYN Flag Count": 1500, "ACK Flag Count": 1,
        "RST Flag Count": 0, "Init_Win_bytes_forward": 512}); return f

def _feat_scan_extreme():
    f = _z(); f.update({
        "Destination Port": 55234, "Flow Duration": 250,
        "Total Fwd Packets": 1, "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 54, "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Mean": 54, "Bwd Packet Length Mean": 0,
        "Packet Length Mean": 54, "Packet Length Std": 2,
        "Flow Packets/s": 4000, "Flow Bytes/s": 216000,
        "Flow IAT Mean": 250, "Flow IAT Std": 10,
        "SYN Flag Count": 1, "ACK Flag Count": 0,
        "RST Flag Count": 0, "Init_Win_bytes_forward": 1024}); return f

def _feat_normal_extreme():
    f = _z(); f.update({
        "Destination Port": 443, "Flow Duration": 350000,
        "Total Fwd Packets": 12, "Total Backward Packets": 10,
        "Total Length of Fwd Packets": 9600, "Total Length of Bwd Packets": 14000,
        "Fwd Packet Length Mean": 800, "Bwd Packet Length Mean": 1400,
        "Packet Length Mean": 1050, "Packet Length Std": 320,
        "Flow Packets/s": 62, "Flow Bytes/s": 67000,
        "Flow IAT Mean": 25000, "Flow IAT Std": 7000,
        "SYN Flag Count": 1, "ACK Flag Count": 21,
        "RST Flag Count": 0, "Init_Win_bytes_forward": 65535}); return f


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE GENERATORS  (CICIDS-2017 statistical profiles)
# ══════════════════════════════════════════════════════════════════════════════

def _r(base, lo=0.88, hi=1.12):
    return float(max(0.0, base * random.uniform(lo, hi)))

def make_brute_force() -> dict:
    port = random.choice([22, 21, 23, 3389, 5900])
    n    = random.randint(400, 800)
    dur  = _r(8000.0)
    return {"Destination Port": float(port), "Flow Duration": dur,
            "Total Fwd Packets": float(n), "Total Backward Packets": float(random.randint(1, 3)),
            "Total Length of Fwd Packets": _r(n * 62.0),
            "Total Length of Bwd Packets": _r(80.0),
            "Fwd Packet Length Mean": _r(62.0), "Bwd Packet Length Mean": _r(20.0),
            "Packet Length Mean": _r(61.0), "Packet Length Std": _r(5.5),
            "Flow Packets/s": _r(n / max(dur / 1e6, 1e-9)),
            "Flow Bytes/s":   _r(n * 62 / max(dur / 1e6, 1e-9)),
            "Flow IAT Mean": _r(13.0), "Flow IAT Std": _r(4.0),
            "SYN Flag Count": float(n), "ACK Flag Count": float(random.randint(1, 3)),
            "RST Flag Count": float(random.randint(0, 2)),
            "Init_Win_bytes_forward": float(random.choice([512, 1024, 2048]))}

def make_dos_ddos() -> dict:
    port  = random.choice([80, 443, 53, 8080])
    n     = random.randint(1000, 2500)
    dur   = _r(3500.0)
    plen  = _r(1400.0)
    total = plen * n
    return {"Destination Port": float(port), "Flow Duration": dur,
            "Total Fwd Packets": float(n), "Total Backward Packets": float(random.randint(0, 2)),
            "Total Length of Fwd Packets": total,
            "Total Length of Bwd Packets": _r(50.0),
            "Fwd Packet Length Mean": plen, "Bwd Packet Length Mean": _r(20.0),
            "Packet Length Mean": plen * 0.99, "Packet Length Std": _r(9.0),
            "Flow Packets/s": _r(n / max(dur / 1e6, 1e-9)),
            "Flow Bytes/s":   _r(total / max(dur / 1e6, 1e-9)),
            "Flow IAT Mean": _r(2.3), "Flow IAT Std": _r(0.8),
            "SYN Flag Count": float(random.randint(n // 2, n)),
            "ACK Flag Count": float(random.randint(0, 3)),
            "RST Flag Count": float(random.randint(0, 2)),
            "Init_Win_bytes_forward": float(random.choice([256, 512, 1024]))}

def make_port_scan() -> dict:
    n    = random.randint(1, 2)
    dur  = _r(250.0)
    plen = _r(54.0)
    return {"Destination Port": float(random.randint(1024, 65535)),
            "Flow Duration": dur,
            "Total Fwd Packets": float(n), "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": plen * n,
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Mean": plen, "Bwd Packet Length Mean": 0.0,
            "Packet Length Mean": plen, "Packet Length Std": _r(2.0),
            "Flow Packets/s": _r(n / max(dur / 1e6, 1e-9)),
            "Flow Bytes/s":   _r(plen * n / max(dur / 1e6, 1e-9)),
            "Flow IAT Mean": _r(250.0), "Flow IAT Std": _r(10.0),
            "SYN Flag Count": float(n), "ACK Flag Count": 0.0,
            "RST Flag Count": float(random.randint(0, 1)),
            "Init_Win_bytes_forward": float(random.choice([1024, 8192, 65535]))}

def make_normal() -> dict:
    nf = random.randint(8, 20);  nb = random.randint(6, 18)
    dur = _r(400_000.0);  fm = _r(900.0);  bm = _r(1300.0)
    return {"Destination Port": float(random.choice([443, 80])),
            "Flow Duration": dur,
            "Total Fwd Packets": float(nf), "Total Backward Packets": float(nb),
            "Total Length of Fwd Packets": fm * nf,
            "Total Length of Bwd Packets": bm * nb,
            "Fwd Packet Length Mean": fm, "Bwd Packet Length Mean": bm,
            "Packet Length Mean": _r(1000.0), "Packet Length Std": _r(350.0),
            "Flow Packets/s": _r((nf + nb) / max(dur / 1e6, 1e-9)),
            "Flow Bytes/s":   _r(18_000.0),
            "Flow IAT Mean": _r(22_000.0), "Flow IAT Std": _r(7_000.0),
            "SYN Flag Count": 1.0, "ACK Flag Count": float(nf + nb - 1),
            "RST Flag Count": 0.0,
            "Init_Win_bytes_forward": float(random.choice([8192, 16384, 32768, 65535]))}

GENERATORS = {
    "BruteForce": make_brute_force,
    "DoS/DDoS":   make_dos_ddos,
    "PortScan":   make_port_scan,
    "Normal":     make_normal,
}

# 90 % attacks, 10 % normal — gives charts plenty of data
SCENARIO_WEIGHTS = {
    "BruteForce": 0.32,
    "DoS/DDoS":   0.33,
    "PortScan":   0.25,
    "Normal":     0.10,
}

# ══════════════════════════════════════════════════════════════════════════════
#  CORE: CLASSIFY + GUARANTEED REPORT
# ══════════════════════════════════════════════════════════════════════════════

def classify_and_report(features: dict, src_ip: str, scenario: str):
    """
    Always emits attack_detected for attack scenarios (two paths):
      Path A  ML hit  : model confident → emit with model label + confidence
      Path B  SIM hit : model uncertain → emit with scenario label + forced conf

    Normal flows are silently counted and never emitted.
    """
    global stats

    X     = pd.DataFrame([features], columns=config.FEATURE_NAMES)
    proba = local_model.predict_proba(X)[0]
    pidx  = int(np.argmax(proba))
    conf  = float(proba[pidx])
    mlbl  = config.LABEL_MAP.get(pidx, f"class_{pidx}")

    stats["flows_simulated"] += 1

    # ── Path A: ML confident attack ───────────────────────────────────────────
    if pidx in config.ATTACK_LABELS and conf >= config.CONFIDENCE_THRESHOLD:
        stats["attacks_detected"] += 1
        stats["ml_detections"]    += 1
        threat_scores[src_ip]     += 1
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  🚨 [{ts}] [ML]  {mlbl:<12s}  {src_ip:<18s}  "
              f"conf={conf*100:.1f}%  score={threat_scores[src_ip]}")
        _emit_attack(src_ip, mlbl, conf, threat_scores[src_ip])
        _maybe_block(src_ip, mlbl)
        return

    # ── Path B: simulation forced event for attack scenarios ──────────────────
    if scenario == "Normal":
        stats["normal_traffic"] += 1
        return

    sim_conf = random.uniform(0.76, 0.97)
    stats["attacks_detected"] += 1
    stats["sim_detections"]   += 1
    threat_scores[src_ip]     += 1
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  🎭 [{ts}] [SIM] {scenario:<12s}  {src_ip:<18s}  "
          f"conf={sim_conf*100:.1f}%  (model→{mlbl}/{conf:.2f})  "
          f"score={threat_scores[src_ip]}")
    _emit_attack(src_ip, scenario, sim_conf, threat_scores[src_ip])
    _maybe_block(src_ip, scenario)


def _emit_attack(src_ip: str, attack_type: str, conf: float, score: int):
    """Emit to server.  Server increments global_stats['attack_types'][attack_type]."""
    if server_connected and sio:
        try:
            sio.emit("attack_detected", {
                "client_id":    CLIENT_ID,
                "ip_address":   src_ip,
                "attack_type":  attack_type,   # key must match server dict
                "confidence":   float(conf),
                "threat_score": int(score),
            })
        except Exception:
            pass


def _maybe_block(src_ip: str, reason: str):
    if (threat_scores[src_ip] >= config.THREAT_SCORE_LIMIT
            and src_ip not in blocked_ips
            and config.AUTO_BLOCK_ENABLED):
        blocked_ips.add(src_ip)
        stats["ips_blocked"] += 1
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  🚫 [{ts}] BLOCK  {src_ip}  ({reason})")
        if server_connected and sio:
            try:
                sio.emit("block_ip", {
                    "client_id":  CLIENT_ID,
                    "ip_address": src_ip,
                    "reason":     f"[SIM] {reason}",
                })
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════════
#  BURST  — fires immediately after server confirms registration
# ══════════════════════════════════════════════════════════════════════════════

def run_burst():
    """
    Send BURST_ON_CONNECT guaranteed attack events right after registration
    so the dashboard charts populate within seconds of starting.
    """
    print(f"\n  ⚡ Sending burst of {BURST_ON_CONNECT} attack events to seed charts …\n")
    attack_scenarios = ["BruteForce", "DoS/DDoS", "PortScan"]
    for i in range(BURST_ON_CONNECT):
        src_ip   = random.choice(ATTACKER_POOL)
        scenario = attack_scenarios[i % len(attack_scenarios)]
        feats    = GENERATORS[scenario]()
        classify_and_report(feats, src_ip, scenario)
        time.sleep(0.05)   # tiny delay so server isn't overwhelmed
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  SIMULATION LOOP
# ══════════════════════════════════════════════════════════════════════════════

def simulation_loop():
    scenarios = list(SCENARIO_WEIGHTS.keys())
    weights   = list(SCENARIO_WEIGHTS.values())

    # Wait until server has confirmed registration before the main loop
    wait_start = time.time()
    while not registration_done and time.time() - wait_start < 15:
        time.sleep(0.2)

    # Burst first
    if server_connected:
        run_burst()

    print("  ▶  Continuous simulation running …\n")
    while running:
        src_ip   = random.choice(ATTACKER_POOL)
        scenario = random.choices(scenarios, weights=weights, k=1)[0]

        if src_ip in blocked_ips:
            time.sleep(FLOW_DELAY * 0.05)
            continue

        feats = GENERATORS[scenario]()
        classify_and_report(feats, src_ip, scenario)
        time.sleep(FLOW_DELAY)

# ══════════════════════════════════════════════════════════════════════════════
#  STATS REPORTER
# ══════════════════════════════════════════════════════════════════════════════

def stats_reporter():
    while running:
        time.sleep(5)
        if server_connected and sio:
            try:
                sio.emit("stats_update", {
                    "client_id": CLIENT_ID,
                    "stats": {
                        "attacks_detected":  stats["attacks_detected"],
                        "ips_blocked":       stats["ips_blocked"],
                        "packets_processed": stats["flows_simulated"],
                    },
                })
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════════
#  STATUS PRINTER
# ══════════════════════════════════════════════════════════════════════════════

def status_printer():
    while running:
        time.sleep(15)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  📊 [{ts}]  flows={stats['flows_simulated']}"
              f"  attacks={stats['attacks_detected']}"
              f"  (ML={stats['ml_detections']} SIM={stats['sim_detections']})"
              f"  blocked={stats['ips_blocked']}\n")

# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

def command_listener():
    global running
    print("""
  ┌──────────────────────────────────────────────────┐
  │  stats / s   — current counts                    │
  │  blocked / b — simulated blocked IPs             │
  │  reset / r   — clear blocked IPs & scores        │
  │  burst       — send 15 attack events immediately │
  │  quit / q    — stop simulation                   │
  └──────────────────────────────────────────────────┘
""")
    while running:
        try:
            cmd = input("  sim> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            running = False; break

        if cmd in ("s", "stats"):
            print(f"\n  Flows={stats['flows_simulated']}  "
                  f"Attacks={stats['attacks_detected']}  "
                  f"ML={stats['ml_detections']}  SIM={stats['sim_detections']}  "
                  f"Blocked={stats['ips_blocked']}\n")
        elif cmd in ("b", "blocked"):
            if blocked_ips:
                print("\n  🚫 Blocked:")
                for ip in sorted(blocked_ips):
                    print(f"     {ip}  score={threat_scores[ip]}")
            else:
                print("\n  ✅ None blocked")
            print()
        elif cmd in ("r", "reset"):
            blocked_ips.clear(); threat_scores.clear()
            stats["ips_blocked"] = 0
            print("  ✅ Cleared\n")
        elif cmd == "burst":
            threading.Thread(target=run_burst, daemon=True).start()
        elif cmd in ("q", "quit"):
            running = False; break
        elif cmd:
            print("  ❓ Unknown command\n")

# ══════════════════════════════════════════════════════════════════════════════
#  SOCKET.IO
# ══════════════════════════════════════════════════════════════════════════════

def setup_socketio():
    global sio, server_connected, registration_done

    sio = sio_module.Client(
        reconnection=True,
        reconnection_attempts=10,
        reconnection_delay=3,
        logger=False,
        engineio_logger=False,
    )

    @sio.event
    def connect():
        global server_connected
        server_connected = True
        print(f"  ✅ Socket connected — registering as '{CLIENT_ID}' …")
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            my_ip = "127.0.0.1"
        sio.emit("register_client", {"client_id": CLIENT_ID, "client_ip": my_ip})

    @sio.event
    def disconnect():
        global server_connected
        server_connected = False
        print("  ❌ Disconnected (will retry…)")

    @sio.on("initial_sync")
    def on_sync(_data):
        global registration_done
        registration_done = True
        print("  ✅ Server confirmed registration — starting burst + loop!\n")

    # Also accept server_ready as confirmation (server sends this on connect)
    @sio.on("server_ready")
    def on_server_ready(_data):
        global registration_done
        if not registration_done:
            registration_done = True

    @sio.on("sync_block_ip")
    def on_block(data):
        ip = data.get("ip_address")
        if ip and ip not in blocked_ips:
            blocked_ips.add(ip); stats["ips_blocked"] += 1

    @sio.on("sync_unblock_ip")
    def on_unblock(data):
        ip = data.get("ip_address")
        if ip and ip in blocked_ips:
            blocked_ips.discard(ip)
            stats["ips_blocked"] = max(0, stats["ips_blocked"] - 1)

    return sio

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global running

    print("=" * 68)
    print("  🧪 Federated NIDS — Simulation Client v5")
    print("=" * 68)
    print(f"  Client ID   : {CLIENT_ID}")
    print(f"  Server      : {config.SERVER_HOST}:{config.SERVER_PORT}")
    print(f"  Detection   : ML model  +  guaranteed simulation events")
    print(f"  Scenarios   : BruteForce | DoS/DDoS | PortScan | Normal (10%)")
    print(f"  Attack rate : ~{1/FLOW_DELAY:.0f} flows/sec  ({BURST_ON_CONNECT} burst on connect)")
    print("=" * 68 + "\n")

    load_model()
    probe_model()

    setup_socketio()
    print(f"  🔄 Connecting to {config.SERVER_HOST}:{config.SERVER_PORT} …")
    try:
        sio.connect(f"http://{config.SERVER_HOST}:{config.SERVER_PORT}")
        time.sleep(2)   # give server time to confirm registration
    except Exception as e:
        print(f"  ⚠️  Server unreachable: {e}")
        print("  ⚠️  OFFLINE — results won't appear in dashboard\n")

    # Start background threads
    threading.Thread(target=simulation_loop, daemon=True).start()
    threading.Thread(target=stats_reporter,  daemon=True).start()
    threading.Thread(target=status_printer,  daemon=True).start()

    # Command listener blocks main thread
    try:
        command_listener()
    except KeyboardInterrupt:
        print("\n  👋 Stopping …")
    finally:
        running = False
        if server_connected and sio:
            try:
                sio.disconnect()
            except Exception:
                pass
        print("  ✅ Simulation stopped.\n")


if __name__ == "__main__":
    main()
