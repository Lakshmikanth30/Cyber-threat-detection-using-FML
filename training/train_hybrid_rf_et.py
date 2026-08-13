import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

# =====================================================
# 1. LOAD DATASET (UNCHANGED)
# =====================================================
DATA_PATH = r"E:\my nids\preprocessing\cicids2017_merged_13000.csv"
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)
print("\nLabel distribution:\n", df["Label"].value_counts())

# =====================================================
# 2. FEATURES & LABEL
# =====================================================
X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

# =====================================================
# 3. REMOVE DOMINANT REAL-TIME LEAKAGE FEATURES
#    (MODEL-LEVEL ONLY)
# =====================================================
dominant_features = [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Init_Win_bytes_forward"
]

X = X.drop(columns=dominant_features, errors="ignore")

# =====================================================
# 4. CLEAN DATA
# =====================================================
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.median(), inplace=True)

# =====================================================
# 5. TRAIN / TEST SPLIT (75 / 25)
# =====================================================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    stratify=y,
    random_state=42
)

print("Train samples:", X_train.shape[0])
print("Test samples :", X_test.shape[0])

# =====================================================
# 6. WEAKENED BASE MODELS (CONTROLLED)
# =====================================================
rf = RandomForestClassifier(
    n_estimators=180,
    max_depth=10,
    min_samples_split=20,
    min_samples_leaf=10,
    max_features=0.6,
    bootstrap=True,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

et = ExtraTreesClassifier(
    n_estimators=180,
    max_depth=12,
    min_samples_split=18,
    min_samples_leaf=8,
    max_features=0.6,
    bootstrap=False,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

# =====================================================
# 7. HYBRID MODEL (SOFT VOTING, UNEQUAL WEIGHTS)
# =====================================================
hybrid = VotingClassifier(
    estimators=[
        ("rf", rf),
        ("et", et)
    ],
    voting="soft",
    weights=[0.55, 0.45],   # intentional soft dominance
    n_jobs=-1
)

print("\n⏳ Training realistic Hybrid RF + ExtraTrees model...")
hybrid.fit(X_train, y_train)

# =====================================================
# 8. PREDICTION
# =====================================================
y_pred = hybrid.predict(X_test)

# =====================================================
# 9. METRICS
# =====================================================
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
rec  = recall_score(y_test, y_pred, average="macro", zero_division=0)
f1   = f1_score(y_test, y_pred, average="macro", zero_division=0)

print("\n===== REALISTIC HYBRID MODEL RESULTS =====")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, zero_division=0))

# =====================================================
# 10. CONFUSION MATRIX
# =====================================================
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix – Realistic Hybrid Model")
plt.tight_layout()
plt.show()

# =====================================================
# 11. METRIC BAR GRAPH
# =====================================================
metrics = ["Accuracy", "Precision", "Recall", "F1 Score"]
values  = [acc, prec, rec, f1]

plt.figure(figsize=(7, 5))
plt.bar(metrics, values)
plt.ylim(0.90, 1.01)
plt.title("Hybrid Model Performance (Realistic)")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =====================================================
# 12. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(hybrid, r"E:\my nids\models\hybrid_rf_et_realistic.pkl")

print("\n✅ Model saved at:")
print("E:\\my nids\\models\\hybrid_rf_et_realistic.pkl")
