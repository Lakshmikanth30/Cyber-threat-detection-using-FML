"""
ENHANCED CONFIGURATION FILE
===========================
Configuration for the Enhanced Federated NIDS system
"""

# =====================================================
# NETWORK CONFIGURATION
# =====================================================

# IMPORTANT: Change this to your server IP address
SERVER_HOST = "127.0.0.1"  # Your server IP - UPDATE THIS!
SERVER_PORT = 5000

# =====================================================
# MODEL PATHS
# =====================================================

MODEL_PATH = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\models\hybrid_federated_optimized.pkl"
FEATURE_PATH = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\models\feature_names.pkl"

# =====================================================
# DETECTION PARAMETERS
# =====================================================

# ML Model confidence threshold
CONFIDENCE_THRESHOLD = 0.75  # 75% confidence required

# Threat scoring (how many detections before auto-block)
THREAT_SCORE_LIMIT = 2  # Block after 2 detections

# Auto-blocking
AUTO_BLOCK_ENABLED = True

# Attack label mapping
LABEL_MAP = {
    0: "BruteForce",
    1: "DoS/DDoS",
    2: "Normal",
    3: "PortScan"
}

ATTACK_LABELS = {0, 1, 3}  # Labels that are considered attacks

# =====================================================
# PACKET CAPTURE SETTINGS
# =====================================================

CAPTURE_INTERFACE = None  # Auto-detect
CAPTURE_FILTER = "tcp or udp"
BUFFER_SIZE = 100
FLOW_TIMEOUT = 45  # seconds

# =====================================================
# CLASSIFICATION SETTINGS
# =====================================================

# Minimum packets before ML classification
MIN_PACKETS_FOR_CLASSIFICATION = 15

# How often to classify (every N packets after minimum)
CLASSIFICATION_INTERVAL = 10

# Rate-based detection thresholds
RATE_DETECTION_ENABLED = True
PACKET_RATE_THRESHOLD = 200   # packets/sec
FLOW_RATE_THRESHOLD = 30       # flows/sec
RATE_DETECTION_CONFIDENCE = 0.85

# =====================================================
# FEDERATED LEARNING PARAMETERS
# =====================================================

LOCAL_EPOCHS = 3
MIN_FLOWS_FOR_TRAINING = 50
UPDATE_INTERVAL = 300  # seconds

# FedAvg parameters
MIN_CLIENTS_FOR_AGGREGATION = 2
AGGREGATION_STRATEGY = "weighted_average"  # based on sample count

# =====================================================
# FILE PATHS
# =====================================================

FIREWALL_RULE_PREFIX = "NIDS_Block_"
BLOCKED_IPS_FILE = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\federated\blocked_ips.json"
LOG_FILE = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\federated\nids.log"

# =====================================================
# LOGGING
# =====================================================

VERBOSE = True
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

# =====================================================
# DASHBOARD SETTINGS
# =====================================================

DASHBOARD_ENABLED = True
DASHBOARD_REFRESH_RATE = 3  # seconds
MAX_ATTACK_HISTORY = 100  # attacks to keep in memory

# =====================================================
# SECURITY SETTINGS
# =====================================================

# Whitelist (these IPs will never be blocked)
WHITELIST_IPS = {
    '127.0.0.1',
    '192.168.0.1',  # Router
    SERVER_HOST      # Server itself
}

# Maximum blocked IPs before warning
MAX_BLOCKED_IPS = 1000

# Auto-unblock after time (seconds, 0 = disabled)
AUTO_UNBLOCK_AFTER = 0  # Disabled by default

print("✅ Configuration loaded successfully")
print(f"   Server: {SERVER_HOST}:{SERVER_PORT}")
print(f"   Model: {MODEL_PATH}")
print(f"   Dashboard: {'Enabled' if DASHBOARD_ENABLED else 'Disabled'}")
