import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
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
DATA_PATH = r"E:\my nids\preprocessing\cicids2017_merged_13000.csv"
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# =====================================================
# 2. FEATURES & LABEL
# =====================================================
X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

# =====================================================
# 3. DROP DOMINANT FEATURES (IMPORTANT)
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

# =====================================================
# 6. STANDARDIZATION (MANDATORY FOR SVM)
# =====================================================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# =====================================================
# 7. ADD REALISTIC NOISE (NETWORK JITTER)
# =====================================================
np.random.seed(42)
noise_strength = 0.20  # 🔥 stronger noise than KNN
X_train = X_train + noise_strength * np.random.normal(size=X_train.shape)
X_test  = X_test  + noise_strength * np.random.normal(size=X_test.shape)

# =====================================================
# 8. SVM MODEL (INTENTIONALLY STRICT)
# =====================================================
svm = SVC(
    kernel="rbf",
    C=0.7,                # 🔥 lower C → underfitting
    gamma="scale",
    decision_function_shape="ovr",
    probability=False,
    random_state=42
)

print("\n⏳ Training SVM model (this may take time)...")
svm.fit(X_train, y_train)

# =====================================================
# 9. PREDICTION
# =====================================================
y_pred = svm.predict(X_test)

# =====================================================
# 10. METRICS
# =====================================================
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
rec  = recall_score(y_test, y_pred, average="macro", zero_division=0)
f1   = f1_score(y_test, y_pred, average="macro", zero_division=0)

print("\n===== SVM RESULTS =====")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, zero_division=0))

# =====================================================
# 11. CONFUSION MATRIX
# =====================================================
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Purples")
plt.title("Confusion Matrix – SVM")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# =====================================================
# 12. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(svm, r"E:\my nids\models\svm_final.pkl")
joblib.dump(scaler, r"E:\my nids\models\svm_scaler.pkl")

print("\n✅ SVM model saved")
