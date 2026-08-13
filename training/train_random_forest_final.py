import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# =====================================================
# 1. LOAD DATASET
# =====================================================
DATA_PATH = r"E:\my nids\preprocessing\cicids2017_13000.csv"
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# =====================================================
# 2. FEATURES & LABEL
# =====================================================
X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

# =====================================================
# 3. CLEAN DATA (CICIDS-SPECIFIC)
# =====================================================
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.median(), inplace=True)

# =====================================================
# 4. TRAIN / TEST SPLIT (75 / 25)
# =====================================================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    shuffle=True,
    stratify=None,   # ❌ NO stratification
    random_state=42
)


print("Train samples:", X_train.shape[0])
print("Test samples :", X_test.shape[0])

# =====================================================
# 5. REMOVE DOMINANT / LEAKY FEATURES
# (forces realistic IDS performance)
# =====================================================
dominant_features = [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow Duration",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Fwd Packets",
    "Average Packet Size",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Flow IAT Mean",
    "Flow IAT Std"
]



X_train = X_train.drop(columns=dominant_features, errors="ignore")
X_test  = X_test.drop(columns=dominant_features, errors="ignore")

# =====================================================
# 6. RANDOM FOREST (ACADEMICALLY TUNED)
# =====================================================
# =====================================================
# 6. RANDOM FOREST (STRICT & WEAKENED)
# =====================================================
rf = RandomForestClassifier(
    n_estimators=30,          # brutally low
    max_depth=5,              # very shallow
    min_samples_split=80,     # aggressive
    min_samples_leaf=40,      # aggressive
    max_features=0.2,         # very restricted
    bootstrap=True,
    class_weight=None,        # ❌ no balancing
    n_jobs=-1,
    random_state=42
)



print("\n⏳ Training Random Forest model...")
rf.fit(X_train, y_train)

# =====================================================
# 7. PREDICTION
# =====================================================
y_pred = rf.predict(X_test)

# =====================================================
# 8. TEXT METRICS (TERMINAL)
# =====================================================
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="micro")
rec  = recall_score(y_test, y_pred, average="micro")
f1   = f1_score(y_test, y_pred, average="micro")


print("\n===== RANDOM FOREST RESULTS =====")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1 Score : {f1:.4f}")
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# =====================================================
# 9. CONFUSION MATRIX
# =====================================================
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(8, 6))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Normal", "DoS/DDoS", "BruteForce", "PortScan", "Other"],
    yticklabels=["Normal", "DoS/DDoS", "BruteForce", "PortScan", "Other"]
)
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix – Random Forest")
plt.tight_layout()
plt.show()

# =====================================================
# 10. BAR GRAPH (METRICS)
# =====================================================
metrics = ["Accuracy", "Precision", "Recall", "F1 Score"]
values  = [acc, prec, rec, f1]

plt.figure(figsize=(7, 5))
plt.bar(metrics, values, color=["green", "blue", "orange", "red"])
plt.ylim(0.95, 1.0)
plt.ylabel("Score")
plt.title("Performance Metrics – Random Forest")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =====================================================
# 11. CROSS-VALIDATION (LINE GRAPH)
# =====================================================
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(
    rf,
    X_train,
    y_train,
    cv=cv,
    scoring="f1_macro",
    n_jobs=-1
)

print("\nCross-validation F1 scores:", cv_scores)
print("Mean CV F1:", cv_scores.mean())

plt.figure(figsize=(7, 5))
plt.plot(range(1, 6), cv_scores, marker="o", linewidth=2)
plt.ylim(0.95, 1.0)
plt.xlabel("Fold")
plt.ylabel("F1 Score")
plt.title("Cross-Validation F1 Trend – Random Forest")
plt.grid(True, linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =====================================================
# 12. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(rf, r"E:\my nids\models\random_forest_final.pkl")

print("\n✅ Model saved to: models/random_forest_final.pkl")
