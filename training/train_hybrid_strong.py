import pandas as pd
import numpy as np
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# =====================================================
# 1. LOAD DATA
# =====================================================
DATA_PATH = r"E:\my nids\preprocessing\cicids2017_13000.csv"
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

# =====================================================
# 2. CLEAN DATA
# =====================================================
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# =====================================================
# 3. TRAIN / TEST SPLIT
# =====================================================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    stratify=y,
    random_state=42
)

# =====================================================
# 4. BASE MODELS (STRONG, NOT OVERFIT)
# =====================================================

rf = RandomForestClassifier(
    n_estimators=400,
    max_depth=16,
    min_samples_leaf=6,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

et = ExtraTreesClassifier(
    n_estimators=400,
    max_depth=16,
    min_samples_leaf=6,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

gb = GradientBoostingClassifier(
    n_estimators=150,
    learning_rate=0.08,
    max_depth=3,
    random_state=42
)

# =====================================================
# 5. HYBRID VOTING MODEL (SOFT)
# =====================================================
hybrid = VotingClassifier(
    estimators=[
        ("rf", rf),
        ("et", et),
        ("gb", gb)
    ],
    voting="soft",
    weights=[2, 2, 1]   # forests dominate
)

# =====================================================
# 6. PIPELINE (SCALING FOR GB)
# =====================================================
pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", hybrid)
])

print("\n⏳ Training STRONG hybrid model...")
pipeline.fit(X_train, y_train)

# =====================================================
# 7. EVALUATION
# =====================================================
y_pred = pipeline.predict(X_test)

print("\n===== HYBRID MODEL RESULTS =====")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# =====================================================
# 8. SAVE MODEL
# =====================================================
os.makedirs(r"E:\my nids\models", exist_ok=True)
joblib.dump(pipeline, r"E:\my nids\models\hybrid_strong.pkl")

print("\n✅ Saved model: hybrid_strong.pkl")
