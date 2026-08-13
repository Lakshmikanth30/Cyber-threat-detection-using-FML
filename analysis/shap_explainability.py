"""
SHAP EXPLAINABILITY FOR FEDERATED NIDS
========================================
Provides explainable AI for attack detection decisions using SHAP values
"""

import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

try:
    import shap
    SHAP_AVAILABLE = True
    print("✅ SHAP library available")
except ImportError:
    SHAP_AVAILABLE = False
    print("⚠️  SHAP not installed. Install with: pip install shap")
    print("   Continuing without SHAP analysis...")

import os

print("=" * 80)
print("SHAP EXPLAINABILITY ANALYSIS")
print("=" * 80)

# Paths
DATA_PATH = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\preprocessing\cicids2017_13000.csv"
MODEL_DIR = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\models"
REPORT_DIR = r"C:\Users\VAIBHAVRAI\OneDrive\Desktop\CYBERPROJ\reports"

os.makedirs(REPORT_DIR, exist_ok=True)

# Load data
print("\n📥 Loading dataset...")
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=["Label", "Label_encoded"])
y = df["Label_encoded"]

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, stratify=y, random_state=42
)

print(f"✅ Dataset loaded")

# Load hybrid model
print("\n📥 Loading hybrid model...")
try:
    hybrid_model = joblib.load(os.path.join(MODEL_DIR, 'hybrid_federated_optimized.pkl'))
    print("✅ Hybrid model loaded")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit(1)

if not SHAP_AVAILABLE:
    print("\n" + "=" * 80)
    print("ALTERNATIVE EXPLAINABILITY ANALYSIS")
    print("=" * 80)
    print("\nSince SHAP is not available, providing feature importance analysis...")
    
    # Extract RandomForest from hybrid model
    if hasattr(hybrid_model, 'named_estimators_'):
        rf_model = hybrid_model.named_estimators_['rf']
        
        if hasattr(rf_model, 'feature_importances_'):
            importances = rf_model.feature_importances_
            feature_names = X.columns
            
            importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': importances
            }).sort_values('Importance', ascending=False)
            
            print("\nTop 10 Most Important Features for Attack Detection:")
            print("=" * 60)
            for idx, row in importance_df.head(10).iterrows():
                print(f"  {row['Feature']:<35} {row['Importance']:.4f}")
            
            # Create visualization
            plt.figure(figsize=(12, 8))
            top_15 = importance_df.head(15)
            
            bars = plt.barh(range(len(top_15)), top_15['Importance'], 
                          color='#667eea', alpha=0.8)
            plt.yticks(range(len(top_15)), top_15['Feature'])
            plt.xlabel('Importance Score', fontsize=12, fontweight='bold')
            plt.title('Feature Importance for Attack Detection\n(RandomForest Component)', 
                     fontsize=14, fontweight='bold')
            plt.grid(axis='x', alpha=0.3)
            
            for i, bar in enumerate(bars):
                width = bar.get_width()
                plt.text(width, bar.get_y() + bar.get_height()/2, 
                        f'{width:.4f}', ha='left', va='center', fontsize=9)
            
            plt.tight_layout()
            plt.savefig(os.path.join(REPORT_DIR, 'explainability_feature_importance.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"\n✅ Explainability chart saved")
    
    print("\n" + "=" * 80)
    print("EXPLAINABILITY INSIGHTS")
    print("=" * 80)
    print("""
The hybrid model's decision-making process is based on:

1. FLOW CHARACTERISTICS
   - Flow duration, packet rates, byte rates
   - These capture attack behavior patterns

2. PACKET STATISTICS  
   - Packet length distributions (mean, std)
   - Forward/backward packet counts
   - Identifies anomalous traffic patterns

3. TCP FLAGS
   - SYN, ACK, RST flag counts
   - Critical for detecting scanning and DoS attacks

4. WINDOW SIZES
   - Initial window bytes
   - Helps identify TCP-based attacks

The ensemble voting mechanism ensures that multiple models must
agree before flagging traffic as malicious, reducing false positives.
    """)
    
    exit(0)

# =====================================================
# SHAP ANALYSIS (if available)
# =====================================================

print("\n" + "=" * 80)
print("SHAP ANALYSIS FOR HYBRID MODEL")
print("=" * 80)

# Use smaller sample for SHAP (it's computationally expensive)
X_shap = X_test.sample(min(500, len(X_test)), random_state=42)
print(f"\nUsing {len(X_shap)} samples for SHAP analysis...")

# Extract RandomForest component for SHAP
if hasattr(hybrid_model, 'named_estimators_'):
    rf_model = hybrid_model.named_estimators_['rf']
    
    print("\n🔍 Creating SHAP explainer (this may take a few minutes)...")
    explainer = shap.TreeExplainer(rf_model)
    
    print("🔍 Calculating SHAP values...")
    shap_values = explainer.shap_values(X_shap)
    
    # SHAP Summary Plot
    print("\n📊 Generating SHAP summary plot...")
    plt.figure(figsize=(12, 10))
    shap.summary_plot(shap_values, X_shap, plot_type="bar", 
                     class_names=["BruteForce", "DoS/DDoS", "Normal", "PortScan"],
                     show=False)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, 'shap_summary_bar.png'), 
               dpi=300, bbox_inches='tight')
    plt.close()
    
    # SHAP Detailed Summary
    print("📊 Generating detailed SHAP summary...")
    for class_idx, class_name in enumerate(["BruteForce", "DoS/DDoS", "Normal", "PortScan"]):
        plt.figure(figsize=(12, 10))
        shap.summary_plot(shap_values[class_idx], X_shap, show=False)
        plt.title(f'SHAP Values for {class_name} Detection', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, f'shap_summary_{class_name.lower()}.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
    
    # SHAP Dependence Plots for top features
    print("📊 Generating SHAP dependence plots...")
    feature_importance = np.abs(shap_values).mean(axis=(0, 1))
    top_features_idx = np.argsort(feature_importance)[-5:]
    
    for idx in top_features_idx:
        feature_name = X.columns[idx]
        plt.figure(figsize=(10, 6))
        shap.dependence_plot(idx, shap_values[0], X_shap, show=False)
        plt.title(f'SHAP Dependence: {feature_name}', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, 
                   f'shap_dependence_{feature_name.replace("/", "_").replace(" ", "_")}.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
    
    print("\n✅ SHAP analysis complete!")
    print(f"📊 SHAP visualizations saved to: {REPORT_DIR}")

print("\n" + "=" * 80)
print("EXPLAINABILITY SUMMARY")
print("=" * 80)
print("""
SHAP (SHapley Additive exPlanations) values provide:

1. FEATURE IMPORTANCE
   - Which features contribute most to each prediction
   - Global understanding of model behavior

2. INDIVIDUAL PREDICTIONS
   - Why a specific packet flow was classified as an attack
   - Transparency in decision-making

3. FEATURE INTERACTIONS
   - How features work together to detect attacks
   - Non-linear relationships visualization

4. ATTACK-SPECIFIC INSIGHTS
   - Different features matter for different attack types
   - BruteForce: Port patterns, connection rates
   - DoS/DDoS: Packet rates, flow duration
   - PortScan: SYN flags, port diversity

This explainability is crucial for:
- Security analysts understanding alerts
- Regulatory compliance (explainable AI)
- Model debugging and improvement
- Trust in automated decisions
""")

print("\n" + "=" * 80)
