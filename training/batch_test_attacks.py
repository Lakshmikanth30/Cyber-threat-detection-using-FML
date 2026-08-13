"""
BATCH ATTACK SIMULATION - AUTOMATED TESTING
Location: E:\my nids\training\batch_test_attacks.py

Simulates different attack scenarios for testing the NIDS
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

print("=" * 70)
print("BATCH ATTACK SIMULATION")
print("=" * 70)
print(f"Model loaded: {MODEL_PATH}")
print()

# =====================================================
# ATTACK SCENARIOS (FROM REAL CICIDS2017 DATA)
# =====================================================

attack_scenarios = [
    {
        "name": "SSH BruteForce Attack #1",
        "source_ip": "192.168.10.50",
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
        },
        "expected": "BruteForce"
    },
    {
        "name": "SSH BruteForce Attack #2",
        "source_ip": "192.168.10.50",
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
        },
        "expected": "BruteForce"
    },
    {
        "name": "FTP BruteForce Attack",
        "source_ip": "192.168.10.51",
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
            "Packet Length Std": 8.082,
            "Flow Packets/s": 500000,
            "Flow Bytes/s": 3500000,
            "Flow IAT Mean": 4,
            "Flow IAT Std": 0,
            "SYN Flag Count": 1,
            "ACK Flag Count": 1,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 229
        },
        "expected": "BruteForce"
    },
    {
        "name": "Normal Web Traffic",
        "source_ip": "192.168.10.100",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 5000,
            "Total Fwd Packets": 5,
            "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 500,
            "Total Length of Bwd Packets": 1500,
            "Fwd Packet Length Mean": 100,
            "Bwd Packet Length Mean": 300,
            "Packet Length Mean": 200,
            "Packet Length Std": 150,
            "Flow Packets/s": 2000,
            "Flow Bytes/s": 400000,
            "Flow IAT Mean": 1000,
            "Flow IAT Std": 200,
            "SYN Flag Count": 1,
            "ACK Flag Count": 8,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 65535
        },
        "expected": "Normal"
    },
    {
        "name": "Port Scan Activity",
        "source_ip": "192.168.10.99",
        "features": {
            "Destination Port": 445,
            "Flow Duration": 100,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 40,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Mean": 40,
            "Bwd Packet Length Mean": 0,
            "Packet Length Mean": 40,
            "Packet Length Std": 0,
            "Flow Packets/s": 10000,
            "Flow Bytes/s": 400000,
            "Flow IAT Mean": 100,
            "Flow IAT Std": 0,
            "SYN Flag Count": 1,
            "ACK Flag Count": 0,
            "RST Flag Count": 0,
            "Init_Win_bytes_forward": 1024
        },
        "expected": "PortScan"
    }
]

# =====================================================
# RUN SIMULATIONS
# =====================================================

print("Running attack simulations...\n")
print("=" * 70)

results = []
correct = 0
total = len(attack_scenarios)

for i, scenario in enumerate(attack_scenarios, 1):
    print(f"\n[Test {i}/{total}] {scenario['name']}")
    print("-" * 70)
    print(f"Source IP: {scenario['source_ip']}")
    print(f"Expected: {scenario['expected']}")
    
    # Create feature vector
    feature_vector = {f: 0.0 for f in FEATURES}
    feature_vector.update(scenario['features'])
    
    # Make prediction
    X = pd.DataFrame([feature_vector])
    proba = model.predict_proba(X)[0]
    pred = np.argmax(proba)
    conf = proba[pred]
    
    predicted_label = LABEL_MAP.get(pred, "Unknown")
    
    # Display results
    print(f"Predicted: {predicted_label} ({conf*100:.2f}% confidence)")
    
    # Show top 3 probabilities
    top3_idx = np.argsort(proba)[-3:][::-1]
    print("\nTop 3 predictions:")
    for idx in top3_idx:
        if idx in LABEL_MAP:
            print(f"  {LABEL_MAP[idx]:<12}: {proba[idx]*100:.2f}%")
    
    # Check if correct
    is_correct = (predicted_label == scenario['expected'])
    if is_correct:
        correct += 1
        print("✅ CORRECT")
    else:
        print("❌ INCORRECT")
    
    results.append({
        "scenario": scenario['name'],
        "source_ip": scenario['source_ip'],
        "expected": scenario['expected'],
        "predicted": predicted_label,
        "confidence": conf,
        "correct": is_correct
    })
    
    print("=" * 70)

# =====================================================
# SUMMARY
# =====================================================
print("\n\n" + "=" * 70)
print("SIMULATION SUMMARY")
print("=" * 70)
print(f"Total tests: {total}")
print(f"Correct predictions: {correct}")
print(f"Accuracy: {correct/total*100:.2f}%")
print("\nDetailed Results:")
print("-" * 70)

for r in results:
    status = "✅" if r['correct'] else "❌"
    print(f"{status} {r['scenario']:<30} | Expected: {r['expected']:<12} | Predicted: {r['predicted']:<12} | Conf: {r['confidence']*100:.2f}%")

print("=" * 70)

# =====================================================
# THREAT ANALYSIS
# =====================================================
print("\n" + "=" * 70)
print("THREAT ANALYSIS")
print("=" * 70)

threat_ips = {}
for r in results:
    ip = r['source_ip']
    if r['predicted'] != "Normal":
        threat_ips[ip] = threat_ips.get(ip, 0) + 1

print("\nIPs with detected threats:")
for ip, count in sorted(threat_ips.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ip}: {count} attack(s) detected")
    if count >= 3:
        print(f"    🚫 RECOMMENDED: Block this IP")

print("=" * 70)

# =====================================================
# SAVE RESULTS
# =====================================================
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
report_path = rf"E:\my nids\reports\batch_test_{timestamp}.txt"

with open(report_path, "w") as f:
    f.write("BATCH ATTACK SIMULATION REPORT\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"Total tests: {total}\n")
    f.write(f"Correct predictions: {correct}\n")
    f.write(f"Accuracy: {correct/total*100:.2f}%\n\n")
    
    for r in results:
        f.write(f"{r['scenario']}\n")
        f.write(f"  Expected: {r['expected']}\n")
        f.write(f"  Predicted: {r['predicted']}\n")
        f.write(f"  Confidence: {r['confidence']*100:.2f}%\n")
        f.write(f"  Result: {'CORRECT' if r['correct'] else 'INCORRECT'}\n\n")

print(f"\n✅ Report saved: {report_path}")
print("\nSimulation complete!")