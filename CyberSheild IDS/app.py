from flask import Flask, render_template, request, redirect, url_for, session
import joblib
import numpy as np
import pandas as pd
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'cybershield_secret_key_2024')  # Change this in production

# Simple user credentials (in production, use database with hashed passwords)
USERS = {
    'admin': 'admin123',
    'user': 'user123'
}

# Load the enhanced models
model = joblib.load('pkl files/ids_model.pkl')
scaler = joblib.load('pkl files/scaler.pkl')
label_encoder = joblib.load('pkl files/label_encoder.pkl')
anomaly_detector = joblib.load('pkl files/anomaly_detector.pkl')
threshold_data = joblib.load('pkl files/optimal_threshold.pkl')
optimal_threshold = threshold_data['threshold']

# Feature names (same order as training)
feature_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

@app.route('/detect')
def detect():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('detect.html')

@app.route('/batch')
def batch():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('batch.html')

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index_dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index_dashboard.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        # Get form data
        features = []
        for feature in feature_names:
            value = request.form.get(feature)
            features.append(float(value))
        
        # Convert to numpy array and scale
        features_array = np.array(features).reshape(1, -1)
        features_scaled = scaler.transform(features_array)
        
        # Multi-class prediction
        prediction_class = model.predict(features_scaled)[0]
        prediction_proba = model.predict_proba(features_scaled)[0]
        attack_category = label_encoder.inverse_transform([prediction_class])[0]
        
        # Binary prediction (Normal vs Attack)
        normal_idx = list(label_encoder.classes_).index('Normal')
        attack_probability = 1 - prediction_proba[normal_idx]
        is_attack = attack_probability >= optimal_threshold
        
        # Anomaly detection
        anomaly_score = anomaly_detector.predict(features_scaled)[0]
        is_anomaly = (anomaly_score == -1)
        
        # Prepare result
        if attack_category == 'Normal' and not is_anomaly:
            result = "Normal Traffic"
            confidence = (1 - attack_probability) * 100
            attack_type = None
        else:
            result = "Attack Detected"
            confidence = attack_probability * 100
            attack_type = attack_category if attack_category != 'Normal' else 'Unknown'
        
        return render_template('detect.html', 
                             prediction_text=f'Prediction: {result}',
                             confidence=f'Confidence: {confidence:.2f}%',
                             attack_type=attack_type,
                             is_anomaly=is_anomaly)
    
    except Exception as e:
        return render_template('detect.html', 
                             prediction_text=f'Error: {str(e)}')

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        # Get uploaded CSV file
        file = request.files['file']
        
        # Read CSV
        df = pd.read_csv(file, header=None)
        
        # Add column names
        columns_with_label = feature_names + ['label']
        
        # Check if file has 41 or 42 columns
        if df.shape[1] == 42:
            df.columns = columns_with_label
            # Remove label column if present
            df = df.drop('label', axis=1)
        elif df.shape[1] == 41:
            df.columns = feature_names
        else:
            return render_template('index.html',
                                 batch_result=f'Error: CSV must have 41 or 42 columns, got {df.shape[1]}')
        
        # Encode categorical columns (protocol_type, service, flag)
        from sklearn.preprocessing import LabelEncoder
        categorical_cols = ['protocol_type', 'service', 'flag']
        
        for col in categorical_cols:
            if df[col].dtype == 'object':  # If it's text, encode it
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
        
        # Scale features
        features_scaled = scaler.transform(df)
        
        # Multi-class predictions
        predictions_class = model.predict(features_scaled)
        predictions_proba = model.predict_proba(features_scaled)
        attack_categories = label_encoder.inverse_transform(predictions_class)
        
        # Binary predictions
        normal_idx = list(label_encoder.classes_).index('Normal')
        attack_probabilities = 1 - predictions_proba[:, normal_idx]
        binary_predictions = (attack_probabilities >= optimal_threshold).astype(int)
        
        # Anomaly detection
        anomaly_scores = anomaly_detector.predict(features_scaled)
        
        # Add predictions to dataframe
        df['Attack_Type'] = attack_categories
        df['Binary_Prediction'] = pd.Series(binary_predictions).map({0: 'Normal', 1: 'Attack'})
        df['Attack_Probability'] = attack_probabilities * 100
        df['Is_Anomaly'] = (anomaly_scores == -1)
        
        # Save results
        df.to_csv('batch_predictions.csv', index=False)
        
        # Count results by category
        normal_count = (binary_predictions == 0).sum()
        attack_count = (binary_predictions == 1).sum()
        
        # Count by attack type
        attack_type_counts = pd.Series(attack_categories).value_counts().to_dict()
        
        result_text = f'Batch prediction complete: {normal_count} Normal, {attack_count} Attacks'
        if attack_count > 0:
            attack_breakdown = ', '.join([f'{count} {atype}' for atype, count in attack_type_counts.items() if atype != 'Normal'])
            result_text += f' ({attack_breakdown})'
        
        return render_template('batch.html',
                             batch_result=result_text,
                             batch_file='batch_predictions.csv')
    
    except Exception as e:
        return render_template('batch.html',
                             batch_result=f'Error: {str(e)}')

if __name__ == '__main__':
    app.run(debug=True)
