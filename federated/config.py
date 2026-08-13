"""
FEDERATED NIDS CONFIGURATION
==============================
All file paths are resolved DYNAMICALLY at runtime relative to this file.
This means the project works on ANY machine / any username / any drive —
no hardcoded paths needed.
"""

import os

# ── Resolve project root from this file's location ──────────────────────────
# This file lives at  <PROJECT_ROOT>/federated/config.py
# So the project root is two levels up from __file__.
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))   # …/federated
_PROJECT_DIR = os.path.dirname(_THIS_DIR)                   # …/CYBERPROJ

# =====================================================
# NETWORK CONFIGURATION
# =====================================================

SERVER_HOST = "127.0.0.1"   # Change to server LAN IP when running multi-machine
SERVER_PORT = 5001

# =====================================================
# MODEL PATHS  (dynamic — works on any machine)
# =====================================================

MODEL_PATH   = os.path.join(_PROJECT_DIR, "models", "hybrid_federated_optimized.pkl")
FEATURE_PATH = os.path.join(_PROJECT_DIR, "models", "feature_names.pkl")

# =====================================================
# DETECTION PARAMETERS
# =====================================================

CONFIDENCE_THRESHOLD   = 0.75   # 75 % confidence required for ML hit
THREAT_SCORE_LIMIT     = 2      # block after N detections
AUTO_BLOCK_ENABLED     = True

LABEL_MAP = {
    0: "BruteForce",
    1: "DoS/DDoS",
    2: "Normal",
    4: "PortScan"
}

ATTACK_LABELS = {0, 1, 4}

# =====================================================
# PACKET CAPTURE SETTINGS
# =====================================================

CAPTURE_INTERFACE = None        # None = auto-detect
CAPTURE_FILTER    = "tcp or udp"
BUFFER_SIZE       = 100
FLOW_TIMEOUT      = 45          # seconds

# =====================================================
# CLASSIFICATION SETTINGS
# =====================================================

MIN_PACKETS_FOR_CLASSIFICATION = 15
CLASSIFICATION_INTERVAL        = 10

RATE_DETECTION_ENABLED     = True
PACKET_RATE_THRESHOLD      = 200
FLOW_RATE_THRESHOLD        = 30
RATE_DETECTION_CONFIDENCE  = 0.85

# =====================================================
# FEDERATED LEARNING
# =====================================================

LOCAL_EPOCHS           = 3
MIN_FLOWS_FOR_TRAINING = 50
UPDATE_INTERVAL        = 300

# =====================================================
# FILE PATHS  (dynamic — works on any machine)
# =====================================================

FIREWALL_RULE_PREFIX = "NIDS_Block_"
BLOCKED_IPS_FILE     = os.path.join(_THIS_DIR, "blocked_ips.json")
LOG_FILE             = os.path.join(_THIS_DIR, "nids.log")

# =====================================================
# LOGGING
# =====================================================

VERBOSE    = True
DEBUG_MODE = False

# =====================================================
# FEATURE NAMES (18 features)
# =====================================================

FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "Init_Win_bytes_forward"
]
