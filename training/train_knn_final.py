import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
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
# 3. DROP DOMINANT FEATURES
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
# 5. TRAIN / TEST SPLIT
# =====================================================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    stratify=y,
    random_state=42
)

# =====================================================
# 6. STANDARDIZE
# =====================================================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# =====================================================
# 7. ADD CONTROLLED NOISE (REALISTIC)
# =====================================================
np.random.seed(42)
noise_strength = 0.15   # 🔥 key knob (0.10–0.20)
X_train = X_train + noise_strength * np.random.normal(size=X_train.shape)
X_test  = X_test  + noise_strength * np.random.normal(size=X_test.shape)

# =====================================================
# 8. KNN (INTENTIONALLY STRESSED)
# =====================================================
knn = KNeighborsClassifier(
    n_neighbors=45,        # 🔥 large k
    weights="uniform",     # 🔥 no distance weighting
    metric="minkowski",
    p=2,
    algorithm="brute",     # slower but neutral
    n_jobs=-1
)

print("\n⏳ Training KNN...")
knn.fit(X_train, y_train)

# =====================================================
# 9. PREDICTION
# =====================================================
y_pred = knn.predict(X_test)

# =====================================================
# 10. METRICS
# =====================================================
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
rec  = recall_score(y_test, y_pred, average="macro", zero_division=0)
f1   = f1_score(y_test, y_pred, average="macro", zero_division=0)

print("\n===== KNN RESULTS =====")
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
sns.heatmap(cm, annot=True, fmt="d", cmap="Reds")
plt.title("Confusion Matrix – KNN")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# =====================================================
# 12. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(knn, r"E:\my nids\models\knn_stressed.pkl")
joblib.dump(scaler, r"E:\my nids\models\knn_scaler.pkl")

print("\n✅KNN model saved")
