"""Geordie AI – Model training (synthetic data only)."""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

FEATURE_NAMES = [
    "packets_per_sec",
    "bytes_per_sec",
    "error_rate",
    "traffic_entropy",
    "active_connections",
    "unique_ports",
]

def generate_synthetic_dataset(samples_per_class: int = 2500, seed: int = 42):
    rng = np.random.default_rng(seed)
    normal = rng.normal(loc=[280, 45000, 0.008, 3.1, 12, 6], scale=[35, 6000, 0.004, 0.25, 3, 2], size=(samples_per_class, 6))
    ddos = rng.normal(loc=[2400, 480000, 0.42, 1.2, 180, 3], scale=[180, 25000, 0.06, 0.15, 25, 1], size=(samples_per_class, 6))
    port_scan = rng.normal(loc=[750, 14000, 0.14, 5.6, 140, 95], scale=[90, 2500, 0.03, 0.35, 18, 12], size=(samples_per_class, 6))
    exfil = rng.normal(loc=[140, 1850000, 0.015, 7.6, 6, 2], scale=[25, 120000, 0.008, 0.2, 2, 1], size=(samples_per_class, 6))

    X = np.clip(np.vstack([normal, ddos, port_scan, exfil]), 0, None)
    y = np.array(["Normal"] * samples_per_class + ["DDoS"] * samples_per_class +
                 ["Port Scan"] * samples_per_class + ["Exfiltration"] * samples_per_class)
    return X, y

def train_models(samples_per_class: int = 2500):
    X, y = generate_synthetic_dataset(samples_per_class)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    iso = IsolationForest(n_estimators=150, contamination=0.18, random_state=42, n_jobs=-1)
    iso.fit(X_train)

    rf = RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1, class_weight="balanced")
    rf.fit(X_train, y_train)

    accuracy = float(rf.score(X_test, y_test))
    return iso, rf, accuracy