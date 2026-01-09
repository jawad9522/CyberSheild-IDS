
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_curve, roc_auc_score, f1_score
from sklearn.model_selection import RandomizedSearchCV
from sklearn.ensemble import IsolationForest
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("="*60)

# Column names
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label"
]

# Load data
print("\n1. Loading data...")
train_df = pd.read_csv("NSL_KDD_DATSET/NSL_KDD_Train.csv", header=None)
train_df.columns = columns
test_df = pd.read_csv("NSL_KDD_DATSET/NSL_KDD_Test.csv", header=None)
test_df.columns = columns
print(f"Training: {train_df.shape}, Test: {test_df.shape}")

# Multi-class attack mapping
print("\n2. Mapping attacks to categories...")
attack_map = {
    'normal': 'Normal',
    'neptune': 'DoS', 'smurf': 'DoS', 'back': 'DoS', 'teardrop': 'DoS', 'pod': 'DoS', 'land': 'DoS',
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'saint': 'Probe', 'mscan': 'Probe',
    'warezclient': 'R2L', 'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 
    'multihop': 'R2L', 'warezmaster': 'R2L', 'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 
    'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
    'buffer_overflow': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R', 'loadmodule': 'U2R', 
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'apache2': 'DoS'
}

train_df['attack_category'] = train_df['label'].map(attack_map).fillna('Unknown')
test_df['attack_category'] = test_df['label'].map(attack_map).fillna('Unknown')

print("\nTrain distribution:")
print(train_df['attack_category'].value_counts())
print("\nTest distribution:")
print(test_df['attack_category'].value_counts())

# Encode categorical features
print("\n3. Encoding features...")
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    train_df[col] = le.fit_transform(train_df[col])
    test_df[col] = test_df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
    le.classes_ = np.append(le.classes_, 'unknown')
    test_df[col] = le.transform(test_df[col])

# FIX: Encode labels using both train and test categories
all_categories = pd.concat([train_df['attack_category'], test_df['attack_category']]).unique()
label_encoder = LabelEncoder()
label_encoder.fit(all_categories)

train_df['label_encoded'] = label_encoder.transform(train_df['attack_category'])
test_df['label_encoded'] = label_encoder.transform(test_df['attack_category'])

print("\nLabel encoding:")
for i, label in enumerate(label_encoder.classes_):
    print(f"{i}: {label}")

# Prepare data
X_train = train_df.drop(['label', 'attack_category', 'label_encoded'], axis=1)
y_train = train_df['label_encoded']
X_test = test_df.drop(['label', 'attack_category', 'label_encoded'], axis=1)
y_test = test_df['label_encoded']

# Scale
print("\n4. Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Hyperparameter tuning
print("\n5. Hyperparameter optimization (10-15 min)...")
param_grid = {
    'n_estimators': [200, 300, 400],
    'max_depth': [8, 10, 12],
    'learning_rate': [0.05, 0.1, 0.15],
    'subsample': [0.7, 0.8, 0.9],
    'colsample_bytree': [0.7, 0.8, 0.9],
    'gamma': [0, 0.1, 0.2]
}

base_model = xgb.XGBClassifier(
    objective='multi:softmax',
    num_class=len(label_encoder.classes_),
    random_state=42,
    n_jobs=-1
)

search = RandomizedSearchCV(base_model, param_grid, n_iter=10, scoring='f1_macro', 
                           cv=3, verbose=2, n_jobs=-1, random_state=42)
search.fit(X_train_scaled, y_train)

print(f"\nBest params: {search.best_params_}")
print(f"Best F1: {search.best_score_:.4f}")
model = search.best_estimator_

# Feature importance
print("\n6. Feature importance...")
feature_importance = pd.DataFrame({
    'feature': X_train.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
print("\nTop 15:")
print(feature_importance.head(15))

plt.figure(figsize=(12, 8))
xgb.plot_importance(model, max_num_features=15, height=0.8)
plt.title('Top 15 Features')
plt.tight_layout()
plt.savefig('results/feature_importance.png', dpi=300)
plt.close()
print("Saved: results/feature_importance.png")

# Predictions
print("\n7. Making predictions...")
y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
f1_macro = f1_score(y_test, y_pred, average='macro')
f1_weighted = f1_score(y_test, y_pred, average='weighted')

print(f"\n{'='*60}")
print("MULTI-CLASS RESULTS")
print(f"{'='*60}")
print(f"Accuracy: {accuracy:.4f}")
print(f"F1-Macro: {f1_macro:.4f}")
print(f"F1-Weighted: {f1_weighted:.4f}")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title('Confusion Matrix')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('results/confusion_matrix.png', dpi=300)
plt.close()
print("\nSaved: results/confusion_matrix.png")

print("\nPer-Class Detection:")
for i, class_name in enumerate(label_encoder.classes_):
    mask = (y_test == i)
    if mask.sum() > 0:
        acc = (y_pred[mask] == i).sum() / mask.sum()
        print(f"{class_name:10s}: {acc:.2%} ({mask.sum()} samples)")

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# Anomaly detection
print(f"\n{'='*60}")
print("ANOMALY DETECTION")
print(f"{'='*60}")
normal_mask = train_df['attack_category'] == 'Normal'
X_normal = X_train_scaled[normal_mask]

iso_forest = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
iso_forest.fit(X_normal)
anomaly_pred = iso_forest.predict(X_test_scaled)

normal_idx = label_encoder.transform(['Normal'])[0]
suspicious = (y_pred == normal_idx) & (anomaly_pred == -1)
actual_attacks = (y_test[suspicious] != normal_idx).sum()

print(f"Anomalies: {(anomaly_pred == -1).sum()}")
print(f"Suspicious: {suspicious.sum()}")
print(f"Actual attacks in suspicious: {actual_attacks}")
if suspicious.sum() > 0:
    print(f"Precision: {actual_attacks/suspicious.sum():.2%}")

# ROC & Threshold
print(f"\n{'='*60}")
print("BINARY: NORMAL VS ATTACK")
print(f"{'='*60}")

y_test_binary = (y_test != normal_idx).astype(int)
y_pred_proba_attack = 1 - y_pred_proba[:, normal_idx]

fpr, tpr, thresholds = roc_curve(y_test_binary, y_pred_proba_attack)
roc_auc = roc_auc_score(y_test_binary, y_pred_proba_attack)
optimal_idx = np.argmax(tpr - fpr)
optimal_threshold = thresholds[optimal_idx]

print(f"ROC AUC: {roc_auc:.4f}")
print(f"Optimal Threshold: {optimal_threshold:.4f}")

plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, 'darkorange', lw=2, label=f'AUC={roc_auc:.3f}')
plt.plot([0,1], [0,1], 'navy', lw=2, linestyle='--')
plt.scatter(fpr[optimal_idx], tpr[optimal_idx], color='red', s=100, 
           label=f'Optimal={optimal_threshold:.3f}', zorder=5)
plt.xlabel('FPR')
plt.ylabel('TPR')
plt.title('ROC Curve')
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('results/roc_curve.png', dpi=300)
plt.close()
print("Saved: results/roc_curve.png")

y_pred_optimal = (y_pred_proba_attack >= optimal_threshold).astype(int)
cm_binary = confusion_matrix(y_test_binary, y_pred_optimal)

print(f"\nBinary Results (threshold={optimal_threshold:.4f}):")
print(f"Accuracy: {accuracy_score(y_test_binary, y_pred_optimal):.4f}")
print(f"Missed: {cm_binary[1][0]}, False Alarms: {cm_binary[0][1]}")
print("\nReport:")
print(classification_report(y_test_binary, y_pred_optimal, target_names=['Normal','Attack']))

# Save models
print(f"\n{'='*60}")
print("SAVING MODELS")
print(f"{'='*60}")

joblib.dump(model, 'pkl files/ids_model.pkl')
joblib.dump(scaler, 'pkl files/scaler.pkl')
joblib.dump(label_encoder, 'pkl files/label_encoder.pkl')
joblib.dump(iso_forest, 'pkl files/anomaly_detector.pkl')
joblib.dump({'threshold': optimal_threshold}, 'pkl files/optimal_threshold.pkl')

print("✓ pkl files/ids_model.pkl")
print("✓ pkl files/scaler.pkl")
print("✓ pkl files/label_encoder.pkl")
print("✓ pkl files/anomaly_detector.pkl")
print("✓ pkl files/optimal_threshold.pkl")

# Save results
results = test_df.copy()
results['Predicted_Category'] = label_encoder.inverse_transform(y_pred)
results['Predicted_Binary'] = y_pred_optimal
results['Predicted_Binary'] = results['Predicted_Binary'].map({0:'Normal',1:'Attack'})
results['Anomaly_Score'] = anomaly_pred
results['Attack_Probability'] = y_pred_proba_attack
results.to_csv('results/IDS_Results.csv', index=False)

print(f"\n{'='*60}")
print("COMPLETED!")
print(f"{'='*60}")
