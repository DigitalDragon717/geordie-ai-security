class AutonomousDecisionEngine:
    def __init__(self, iso_model, rf_model):
        self.iso_model = iso_model
        self.rf_model = rf_model

    def process_telemetry(self, feature_vector):
        """
        Features: [packets_sec, bytes_sec, error_rate, traffic_entropy, conn_rate, unique_ports]
        """
        # Step 1: Unsupervised Anomaly Check
        anomaly_score = self.iso_model.decision_function([feature_vector])[0]
        is_anomaly = self.iso_model.predict([feature_vector])[0] == -1

        # Step 2: Supervised Classification
        threat_type = self.rf_model.predict([feature_vector])[0]
        probabilities = self.rf_model.predict_proba([feature_vector])[0]
        confidence = max(probabilities) * 100

        # Step 3: Risk Score Calculation (0-100)
        risk_score = min(100, int((abs(anomaly_score) * 50) + (confidence * 0.5)))

        # Step 4: Autonomous Response Selection
        action = "MONITOR"
        if is_anomaly and confidence > 85.0 and threat_type != 'NORMAL':
            if threat_type == 'DDoS':
                action = "REAL_FIREWALL_BLOCK"
            elif threat_type == 'Port Scan':
                action = "PORT_CONTAINMENT"
            elif threat_type == 'Exfiltration':
                action = "PROCESS_ISOLATION"

        # Step 5: Dynamic MITRE & NIST Mapping
        mitre_map = {"DDoS": "T1498", "Port Scan": "T1046", "Exfiltration": "T1048", "NORMAL": "N/A"}
        nist_map = {"DDoS": "DE.AE-1", "Port Scan": "PR.PT-4", "Exfiltration": "DE.CM-1", "NORMAL": "N/A"}

        return {
            "is_anomaly": is_anomaly,
            "threat_type": threat_type,
            "confidence": round(confidence, 2),
            "risk_score": risk_score,
            "action": action,
            "mitre_id": mitre_map.get(threat_type, "N/A"),
            "nist_control": nist_map.get(threat_type, "N/A")
        }