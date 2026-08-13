"""
REALISTIC ATTACK TESTING - Based on Actual CICIDS2017 Patterns
Location: E:\my nids\training\test_simple_attacks.py

Test scenarios using REAL patterns from your dataset
Dataset: 1500 PortScan, 2300 BruteForce, 4000 DoS, 4100 Normal
"""

import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# =====================================================
# LOAD MODEL
# =====================================================
MODEL_PATH = r"E:\my nids\models\hybrid_federated_optimized.pkl"
FEATURE_PATH = r"E:\my nids\models\feature_names.pkl"

model = joblib.load(MODEL_PATH)
FEATURES = joblib.load(FEATURE_PATH)

LABEL_MAP = {
    0: "BruteForce",
    1: "DoS/DDoS",
    2: "Normal",
    4: "PortScan"
}

ATTACK_LABELS = {0, 1, 4}

print("=" * 70)
print("REALISTIC ATTACK TESTING - CICIDS2017 PATTERNS")
print("=" * 70)
print(f"✅ Model loaded")
print(f"✅ Features: {len(FEATURES)}")
print(f"📊 Dataset distribution:")
print(f"   • PortScan: ~1500 samples")
print(f"   • BruteForce: ~2300 samples")
print(f"   • DoS/DDoS: ~4000 samples")
print(f"   • Normal: ~4100 samples\n")

# =====================================================
# REALISTIC ATTACK SCENARIOS (FROM YOUR ACTUAL DATA)
# =====================================================

scenarios = {
    "1": {
        "name": "SSH BruteForce #1 (Short Duration)",
        "source_ip": "192.168.1.50",
        "features": {
            "Destination Port": 22,
            "Flow Duration": 74,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 0,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 0,
            "Packet Length Std": 0,
            "Flow Packets/s": 27027.027,
            "Flow Bytes/s": 0,
            "Flow IAT Mean": 74,
            "Flow IAT Std": 0,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 259
        }
    },
    "2": {
        "name": "SSH BruteForce #2 (Long Duration)",
        "source_ip": "192.168.1.50",
        "features": {
            "Destination Port": 22,
            "Flow Duration": 11584764,
            "Total Fwd Packets": 21,
            "Total Backward Packets": 32,
            "Total Length of Fwd Packets": 2008,
            "Total Length of Bwd Packets": 2745,
            "Fwd Packet Length Mean": 95.619,
            "Bwd Packet Length Mean": 85.781,
            "Packet Length Mean": 88.018,
            "Packet Length Std": 189.590,
            "Flow Packets/s": 4.575,
            "Flow Bytes/s": 410.280,
            "Flow IAT Mean": 222783.923,
            "Flow IAT Std": 599181.261,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 29200
        }
    },
    "3": {
        "name": "FTP BruteForce Attack",
        "source_ip": "192.168.1.51",
        "features": {
            "Destination Port": 21,
            "Flow Duration": 4,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 14,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 7,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 9.333,
            "Packet Length Std": 8.083,
            "Flow Packets/s": 500000,
            "Flow Bytes/s": 3500000,
            "Flow IAT Mean": 4,
            "Flow IAT Std": 0,
            "SYN Flag Count": 1,
            "ACK Flag Count": 1,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 229
        }
    },
    "4": {
        "name": "DoS/DDoS Attack #1 (Slowloris - Long Connection)",
        "source_ip": "192.168.1.99",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 98846619,  # 98.8 seconds - KEY!
            "Total Fwd Packets": 6,
            "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 379,
            "Total Length of Bwd Packets": 11595,
            "Fwd Packet Length Mean": 63.167,
            "Bwd Packet Length Mean": 2319,
            "Packet Length Mean": 997.833,
            "Packet Length Std": 2908.153,
            "Flow Packets/s": 0.111,  # Very low!
            "Flow Bytes/s": 121.137,
            "Flow IAT Mean": 9884661.9,
            "Flow IAT Std": 31200000,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 274
        }
    },
    "5": {
        "name": "DoS/DDoS Attack #2 (High Duration)",
        "source_ip": "192.168.1.98",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 109608672,  # 109.6 seconds
            "Total Fwd Packets": 4,
            "Total Backward Packets": 3,
            "Total Length of Fwd Packets": 532,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 133,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 66.5,
            "Packet Length Std": 183.290,
            "Flow Packets/s": 0.064,  # Very low!
            "Flow Bytes/s": 4.854,
            "Flow IAT Mean": 18300000,
            "Flow IAT Std": 44700000,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 29200
        }
    },
    "6": {
        "name": "DoS/DDoS Attack #3 (Short Burst)",
        "source_ip": "192.168.1.97",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 984,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 0,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 0,
            "Packet Length Std": 0,
            "Flow Packets/s": 2032.520,
            "Flow Bytes/s": 0,
            "Flow IAT Mean": 984,
            "Flow IAT Std": 0,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 251
        }
    },
    "7": {
        "name": "Port Scan #1 (Port 1494)",
        "source_ip": "192.168.1.88",
        "features": {
            "Destination Port": 1494,
            "Flow Duration": 23,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 6,
            "Fwd Packet Length Mean": 0,
            "Bwd Packet Length Mean": 6,
            "Packet Length Mean": 2,
            "Packet Length Std": 3.464,  # KEY SIGNATURE!
            "Flow Packets/s": 86956.522,
            "Flow Bytes/s": 260869.565,
            "Flow IAT Mean": 23,
            "Flow IAT Std": 0,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 29200
        }
    },
    "8": {
        "name": "Port Scan #2 (Port 445 - SMB)",
        "source_ip": "192.168.1.87",
        "features": {
            "Destination Port": 445,
            "Flow Duration": 471,
            "Total Fwd Packets": 3,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 0,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 0,
            "Packet Length Std": 0,
            "Flow Packets/s": 8492.569,
            "Flow Bytes/s": 0,
            "Flow IAT Mean": 157,
            "Flow IAT Std": 258.170,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 29200
        }
    },
    "9": {
        "name": "Port Scan #3 (Port 9415)",
        "source_ip": "192.168.1.86",
        "features": {
            "Destination Port": 9415,
            "Flow Duration": 73,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": 2,
            "Total Length of Bwd Packets": 6,
            "Fwd Packet Length Mean": 2,
            "Bwd Packet Length Mean": 6,
            "Packet Length Mean": 3.333,
            "Packet Length Std": 2.309,  # Close to signature
            "Flow Packets/s": 27397.260,
            "Flow Bytes/s": 109589.041,
            "Flow IAT Mean": 73,
            "Flow IAT Std": 0,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 1024
        }
    },
    "10": {
        "name": "Normal DNS Traffic (Port 53)",
        "source_ip": "192.168.1.100",
        "features": {
            "Destination Port": 53,
            "Flow Duration": 48771,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 64,
            "Total Length of Bwd Packets": 328,
            "Fwd Packet Length Mean": 32,
            "Bwd Packet Length Mean": 164,
            "Packet Length Mean": 84.8,
            "Packet Length Std": 72.299,
            "Flow Packets/s": 82.016,
            "Flow Bytes/s": 8037.563,
            "Flow IAT Mean": 16257,
            "Flow IAT Std": 28112.926,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": -1
        }
    },
    "11": {
        "name": "Normal HTTPS Traffic (Port 443)",
        "source_ip": "192.168.1.101",
        "features": {
            "Destination Port": 443,
            "Flow Duration": 326442,
            "Total Fwd Packets": 15,
            "Total Backward Packets": 11,
            "Total Length of Fwd Packets": 974,
            "Total Length of Bwd Packets": 7387,
            "Fwd Packet Length Mean": 64.933,
            "Bwd Packet Length Mean": 671.545,
            "Packet Length Mean": 309.667,
            "Packet Length Std": 563.347,
            "Flow Packets/s": 79.647,
            "Flow Bytes/s": 25612.513,
            "Flow IAT Mean": 13057.68,
            "Flow IAT Std": 24885.551,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 65535
        }
    },
    "12": {
        "name": "Normal HTTP Traffic (Port 80)",
        "source_ip": "192.168.1.102",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 115944066,
            "Total Fwd Packets": 18,
            "Total Backward Packets": 15,
            "Total Length of Fwd Packets": 870,
            "Total Length of Bwd Packets": 1492,
            "Fwd Packet Length Mean": 48.333,
            "Bwd Packet Length Mean": 99.467,
            "Packet Length Mean": 69.471,
            "Packet Length Std": 200.559,
            "Flow Packets/s": 0.285,
            "Flow Bytes/s": 20.372,
            "Flow IAT Mean": 3623252.063,
            "Flow IAT Std": 4769299.615,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 29200
        }
    }
}

# =====================================================
# TEST FUNCTION
# =====================================================

def test_scenario(scenario_num):
    """Test a specific scenario"""
    if scenario_num not in scenarios:
        print(f"❌ Scenario {scenario_num} not found")
        return
    
    scenario = scenarios[scenario_num]
    
    print("\n" + "=" * 70)
    print(f"Testing: {scenario['name']}")
    print("=" * 70)
    print(f"Source IP: {scenario['source_ip']}")
    
    # Create feature vector
    feature_vector = {f: 0.0 for f in FEATURES}
    feature_vector.update(scenario['features'])
    
    # Make prediction
    X = pd.DataFrame([feature_vector])
    proba = model.predict_proba(X)[0]

    best_idx = np.argmax(proba)
    pred = model.classes_[best_idx]   # ✅ FIX
    conf = proba[best_idx]            # ✅ FIX

    predicted_label = LABEL_MAP[pred] # ✅ FIX

    
    # Display results
    print(f"\n🎯 Predicted Class: {predicted_label}")
    print(f"🔒 Confidence: {conf*100:.2f}%")
    
    # Show all probabilities
    print("\nClass Probabilities:")
    sorted_proba = sorted(enumerate(proba), key=lambda x: x[1], reverse=True)
    for idx, prob in sorted_proba:
        if idx in LABEL_MAP:
            bar = "█" * int(prob * 50)
            print(f"  {LABEL_MAP[idx]:<12}: {prob*100:5.2f}% {bar}")
    
    # Attack detection
    if pred in ATTACK_LABELS and conf >= 0.75:
        print("\n⚠️  INTRUSION DETECTED ⚠️")
        print(f"Attack Type: {predicted_label}")
        print(f"Recommended Action: Block IP {scenario['source_ip']}")
    elif pred in ATTACK_LABELS:
        print(f"\n⚠️  POSSIBLE INTRUSION (Low Confidence)")
        print(f"Recommended Action: Monitor IP {scenario['source_ip']}")
    else:
        print("\n✅ Traffic is Normal")
    
    print("=" * 70)

# =====================================================
# INTERACTIVE MENU
# =====================================================

def show_menu():
    print("\n" + "=" * 70)
    print("ATTACK SIMULATION MENU - REAL CICIDS2017 PATTERNS")
    print("=" * 70)
    print("\n🔴 BRUTE FORCE ATTACKS:")
    print("  1. SSH BruteForce #1 (Short Duration - 74μs)")
    print("  2. SSH BruteForce #2 (Long Duration - 11.5s)")
    print("  3. FTP BruteForce Attack")
    print("\n🔴 DoS/DDoS ATTACKS:")
    print("  4. DoS/DDoS #1 (Slowloris - 98.8s)")
    print("  5. DoS/DDoS #2 (High Duration - 109.6s)")
    print("  6. DoS/DDoS #3 (Short Burst)")
    print("\n🔴 PORT SCAN ATTACKS:")
    print("  7. Port Scan #1 (Port 1494)")
    print("  8. Port Scan #2 (Port 445 - SMB)")
    print("  9. Port Scan #3 (Port 9415)")
    print("\n🟢 NORMAL TRAFFIC:")
    print("  10. Normal DNS Traffic (Port 53)")
    print("  11. Normal HTTPS Traffic (Port 443)")
    print("  12. Normal HTTP Traffic (Port 80)")
    print("\n📊 COMMANDS:")
    print("  all    : Test all scenarios")
    print("  brute  : Test all BruteForce (1-3)")
    print("  dos    : Test all DoS (4-6)")
    print("  scan   : Test all PortScan (7-9)")
    print("  normal : Test all Normal (10-12)")
    print("  menu   : Show this menu")
    print("  exit   : Exit program")
    print("=" * 70)

# =====================================================
# MAIN LOOP
# =====================================================

show_menu()

while True:
    try:
        cmd = input("\n>> ").strip().lower()
        
        if cmd == "exit":
            print("\n👋 Exiting...\n")
            break
        
        if cmd == "menu":
            show_menu()
            continue
        
        if cmd == "all":
            for num in scenarios.keys():
                test_scenario(num)
            continue
        
        if cmd == "brute":
            for num in ["1", "2", "3"]:
                test_scenario(num)
            continue
        
        if cmd == "dos":
            for num in ["4", "5", "6"]:
                test_scenario(num)
            continue
        
        if cmd == "scan":
            for num in ["7", "8", "9"]:
                test_scenario(num)
            continue
        
        if cmd == "normal":
            for num in ["10", "11", "12"]:
                test_scenario(num)
            continue
        
        if cmd in scenarios.keys():
            test_scenario(cmd)
        else:
            print("❌ Invalid command. Type 'menu' to see options.")
    
    except KeyboardInterrupt:
        print("\n\n👋 Exiting...\n")
        break
    except Exception as e:
        print(f"❌ Error: {e}")