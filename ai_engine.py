import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

def generate_production_dataset(samples_per_class=2000):
    """Generates a multi-feature dataset representing real network telemetry."""
    np.random.seed(42)
    
    # Feature set: [packets_sec, bytes_sec, error_rate, traffic_entropy, conn_rate, unique_ports]
    normal = np.random.normal(loc=[300, 50000, 0.01, 3.2, 10, 5], scale=[40, 5000, 0.005, 0.2, 2, 1], size=(samples_per_class, 6))
    ddos = np.random.normal(loc=[2500, 500000, 0.45, 1.1, 200, 2], scale=[200, 20000, 0.05, 0.1, 20, 1], size=(samples_per_class, 6))
    port_scan = np.random.normal(loc=[800, 15000, 0.15, 5.8, 150, 100], scale=[100, 2000, 0.02, 0.3, 15, 10], size=(samples_per_class, 6))
    exfiltration = np.random.normal(loc=[150, 2000000, 0.02, 7.8, 5, 1], scale=[20, 100000, 0.01, 0.1, 1, 1], size=(samples_per_class, 6))
    
    X = np.vstack([normal, ddos, port_scan, exfiltration])
    y = np.array(['NORMAL']*samples_per_class + ['DDoS']*samples_per_class + ['Port Scan']*samples_per_class + ['Exfiltration']*samples_per_class)
    
    return X, y

def train_and_persist_models():
    """Trains both Unsupervised and Supervised models on startup."""
    X, y = generate_production_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_split_size=0.2, random_state=42)
    
    # 1. Unsupervised Anomaly Engine
    iso_forest = IsolationForest(contamination=0.25, random_state=42)
    iso_forest.fit(X_train)
    
    # 2. Supervised Threat Classifier
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_classifier.fit(X_train, y_train)
    
    # Calculate test accuracy
    accuracy = rf_classifier.score(X_test, y_test)
    
    return iso_forest, rf_classifier, accuracy