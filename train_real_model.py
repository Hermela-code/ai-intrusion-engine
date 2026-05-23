import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

print("[*] Loading real NSL-KDD datasets...")

# Define the core columns we care about (mapping to our Scapy capabilities)
# Column indices based on standard NSL-KDD CSV layouts
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Read the CSV files
train_df = pd.read_csv('data/KDDTrain+.csv', names=columns, header=None)
test_df = pd.read_csv('data/KDDTest+.csv', names=columns, header=None)

# 1. Simplify Labels into Classes: Normal (0), Port Scan/Probe (1), DoS (2)
# Any other advanced attacks (R2L/U2R) will be grouped into general anomalies or Normal for scope
def group_label(label):
    label = str(label).lower().strip('.')
    if label == 'normal':
        return 0
    elif label in ['satan', 'ipsweep', 'portsweep', 'nmap', 'mscan', 'saint']:
        return 1  # Port Scan / Probes
    elif label in ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'udpstorm', 'processtable', 'mailbomb']:
        return 2  # DoS
    else:
        return 0  # Fallback to normal or non-scoped threat for simplification

train_df['target'] = train_df['label'].apply(group_label)
test_df['target'] = test_df['label'].apply(group_label)

# 2. Select Features we can realistically extract live using Scapy in Phase 2
# We focus on basic traffic signatures and rapid counting stats
features_to_use = [
    'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 
    'dst_host_count', 'dst_host_srv_count'
]

X_train = train_df[features_to_use]
y_train = train_df['target']

X_test = test_df[features_to_use]
y_test = test_df['target']

print(f"[*] Dataset shapes - Train: {X_train.shape}, Test: {X_test.shape}")
print("[*] Training Random Forest Classifier on NSL-KDD signatures...")

# Initialize and fit model
model = RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate performance
y_pred = model.predict(X_test)
print(f"\n[+] Model Accuracy on Test Data: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Port Scan', 'DoS']))

# Save everything out for Phase 2
model_filename = 'idps_real_model.pkl'
joblib.dump(model, model_filename)
print(f"\n[+] AI Engine successfully saved to '{model_filename}'")