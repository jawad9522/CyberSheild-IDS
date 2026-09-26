# CyberSheild-IDS
AI-based Intrusion Detection System using XGBoost for classification and anomaly detection.

## 🚀 Features

- **Multi-class Attack Detection**: Classifies network traffic into Normal, DoS, Probe, R2L, and U2R categories  
- **Anomaly Detection**: Uses Isolation Forest for additional anomaly detection layer  
- **Web Interface**: Flask-based dashboard for single and batch predictions  
- **High Accuracy**: Trained on NSL-KDD dataset with optimized hyperparameters  
- **Real-time Detection**: Instant classification of network traffic patterns  

---

## 🧨 Attack Categories

- **Normal**: Legitimate network traffic  
- **DoS**: Denial of Service attacks (neptune, smurf, back, etc.)  
- **Probe**: Surveillance and probing attacks (satan, ipsweep, nmap, etc.)  
- **R2L**: Remote to Local attacks (warezclient, guess_passwd, etc.)  
- **U2R**: User to Root attacks (buffer_overflow, rootkit, etc.)  

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/jawad9522/network-ids.git
cd network-ids

# Create a virtual environment
python -m venv venv

# Activate environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Optional**: Create a `.env` file with:
```
FLASK_SECRET_KEY=your-secret-key-here
```

---

## 📈 Usage

### 🔧 Training the Model

```bash
python IDS.PY
```

This will:
- Load and preprocess the NSL-KDD dataset  
- Train XGBoost classifier with hyperparameter optimization  
- Train Isolation Forest for anomaly detection  
- Generate performance visualizations  
- Save trained models to `pkl files/` directory  

### 🌐 Running the Web Application

```bash
python app.py
```

Access the dashboard at: [http://localhost:5000](http://localhost:5000)

**Default Login Credentials**:
- `admin` / `admin123`  
- `user` / `user123`  

### 🧪 Single Prediction
1. Go to the **Detect** page  
2. Enter 41 network traffic features  
3. Click **Predict** to view classification results  

### 📁 Batch Prediction
1. Go to the **Batch** page  
2. Upload a CSV file with 41 or 42 columns  
3. Download results with predictions and confidence scores  

---

## 📊 Dataset

This project uses the **NSL-KDD** dataset (an improved version of KDD Cup 1999):

- Training set: 125,973 records  
- Test set: 22,544 records  
- 41 features per record  
- 5 attack categories  

Dataset is located in the `NSL_KDD_DATSET/` directory.

---

## 📈 Model Performance

- **Accuracy**: ~99% on test set  
- **F1-Score**: High across all attack categories  
- **ROC AUC**: >0.99 for binary classification (Normal vs Attack)  
- **Anomaly Detection**: Additional layer for zero-day attack detection  

---

## 🗂️ Project Structure

```
.
├── app.py                      # Flask web application
├── IDS.PY                      # Model training script
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
├── NSL_KDD_DATSET/            # Dataset files
│   ├── NSL_KDD_Train.csv
│   └── NSL_KDD_Test.csv
├── pkl files/                  # Trained models
│   ├── ids_model.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   ├── anomaly_detector.pkl
│   └── optimal_threshold.pkl
├── templates/                  # HTML templates
│   ├── index_dashboard.html
│   ├── login.html
│   ├── detect.html
│   └── batch.html
└── results/                    # Performance visualizations & results
    ├── confusion_matrix.png
    ├── feature_importance.png
    ├── roc_curve.png
    └── IDS_Results.csv
```

---

## 🧪 Technologies Used

- Python 3.8+  
- Flask  
- XGBoost  
- Scikit-learn  
- Pandas & NumPy  
- Matplotlib & Seaborn  

---

## 🔐 Security Notes

**Important for production**:
- Change the Flask secret key in `app.py` or use environment variables  
- Implement proper user authentication with hashed passwords  
- Use HTTPS for secure communication  
- Add rate limiting and input validation  
- Store credentials in a secure database  

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.

---

## Acknowledgments

- NSL-KDD dataset creators  
- XGBoost and scikit-learn communities  


