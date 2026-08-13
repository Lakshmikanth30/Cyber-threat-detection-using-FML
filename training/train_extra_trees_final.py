import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

# =====================================================
# 1. LOAD DATASET
# =====================================================
DATA_PATH = r"E:\my nids\preprocessing\cicids2017_merged_13000.csv"
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# =====================================================
# 2. FEATURES & LABEL
# =====================================================
X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

# =====================================================
# 3. CLEAN DATA
# =====================================================
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.median(), inplace=True)

# =====================================================
# 4. TRAIN / TEST SPLIT (75 / 25)
# =====================================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    stratify=y,
    random_state=7
)

# =====================================================
# 5. REMOVE DOMINANT FEATURES (ANTI-LEAKAGE)
# =====================================================
dominant_features = [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Init_Win_bytes_forward"
]

X_train = X_train.drop(columns=dominant_features, errors="ignore")
X_test  = X_test.drop(columns=dominant_features, errors="ignore")

# =====================================================
# 6. EXTRA TREES MODEL (REAL-TIME OPTIMIZED)
# =====================================================
et = ExtraTreesClassifier(
    n_estimators=700,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    max_features="sqrt",
    bootstrap=False,                 # key difference from RF
    class_weight="balanced",
    n_jobs=-1,
    random_state=7
)

print("\n⏳ Training Extra Trees model...")
et.fit(X_train, y_train)

# =====================================================
# 7. PREDICTION
# =====================================================
y_pred = et.predict(X_test)

# =====================================================
# 8. METRICS
# =====================================================
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="macro")
rec  = recall_score(y_test, y_pred, average="macro")
f1   = f1_score(y_test, y_pred, average="macro")

print("\n===== EXTRA TREES RESULTS =====")
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
    cmap="Greens",
    xticklabels=["Normal", "DoS/DDoS", "BruteForce", "PortScan", "Other"],
    yticklabels=["Normal", "DoS/DDoS", "BruteForce", "PortScan", "Other"]
)
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix – Extra Trees")
plt.tight_layout()
plt.show()

# =====================================================
# 10. BAR GRAPH
# =====================================================
metrics = ["Accuracy", "Precision", "Recall", "F1 Score"]
values  = [acc, prec, rec, f1]

plt.figure(figsize=(7, 5))
plt.bar(metrics, values, color=["#2E7D32", "#1565C0", "#EF6C00", "#6A1B9A"])
plt.ylim(0.95, 1.0)
plt.ylabel("Score")
plt.title("Performance Metrics – Extra Trees")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =====================================================
# 11. CROSS-VALIDATION
# =====================================================
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(
    et,
    X,
    y,
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
plt.title("Cross-Validation F1 Trend – Extra Trees")
plt.grid(True, linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =====================================================
# 12. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(et, r"E:\my nids\models\extra_trees_final.pkl")

print("\n✅ Extra Trees model saved to models/extra_trees_final.pkl")
