"""Geordie AI – Decision logic only (no enforcement)."""
from typing import Dict, Any, List
import numpy as np

class DecisionEngine:
    def __init__(self, iso_model, rf_model):
        self.iso = iso_model
        self.rf = rf_model
        self.mitre_map = {
            "DDoS": "T1498 – Network Denial of Service",
            "Port Scan": "T1046 – Network Service Discovery",
            "Exfiltration": "T1048 – Exfiltration Over Alternative Protocol",
            "Normal": "N/A",
        }
        self.nist_map = {
            "DDoS": "DE.AE-1 – Anomalies and Events",
            "Port Scan": "PR.PT-4 – Communications and Control Protection",
            "Exfiltration": "DE.CM-1 – Network Monitoring",
            "Normal": "N/A",
        }

    def evaluate(self, features: List[float]) -> Dict[str, Any]:
        vec = np.asarray(features, dtype=float).reshape(1, -1)
        anomaly_score = float(self.iso.decision_function(vec)[0])
        is_anomaly = int(self.iso.predict(vec)[0]) == -1
        threat = str(self.rf.predict(vec)[0])
        confidence = float(np.max(self.rf.predict_proba(vec)[0]) * 100.0)

        risk = min(100, int(abs(anomaly_score) * 55 + confidence * 0.45))
        if threat == "Normal":
            risk = max(1, int(risk * 0.12))

        action = "MONITOR"
        if is_anomaly and confidence >= 80.0 and threat != "Normal":
            if threat == "DDoS":
                action = "RECOMMEND_FIREWALL_BLOCK"
            elif threat == "Port Scan":
                action = "RECOMMEND_PORT_CONTAINMENT"
            elif threat == "Exfiltration":
                action = "RECOMMEND_PROCESS_REVIEW"

        return {
            "is_anomaly": is_anomaly,
            "threat_type": threat,
            "anomaly_score": round(anomaly_score, 4),
            "confidence": round(confidence, 2),
            "risk_score": risk,
            "action": action,
            "mitre_id": self.mitre_map.get(threat, "N/A"),
            "nist_control": self.nist_map.get(threat, "N/A"),
        }