import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings("ignore")

TRAINING_DATA = [
    [1,0,0,0,0,1],[2,0,0,0,0,2],[1,0,0,0,0,1],[2,0,0,0,0,3],[3,0,0,0,0,3],[1,0,0,0,0,2],[2,0,0,0,0,2],
    [3,0,0,1,0,5],[4,0,0,1,0,6],[3,0,0,1,0,5],[5,0,0,1,0,7],[4,0,1,0,0,7],[3,0,1,0,0,6],[2,0,0,1,0,5],
    [6,1,0,1,1,14],[5,1,1,1,0,15],[7,1,1,1,1,18],[4,1,0,1,1,12],[5,0,1,1,1,13],[6,1,1,0,1,16],[8,1,1,1,1,20],
]
TRAINING_LABELS = ["LOW"]*7 + ["MEDIUM"]*7 + ["HIGH"]*7
NORMAL_BASELINE = [
    [1,0,0,0,0,1],[2,0,0,0,0,2],[2,0,0,0,0,3],[3,0,0,0,0,3],
    [1,0,0,0,0,2],[2,0,0,1,0,4],[3,0,0,1,0,5],
]

class NetSentinelAI:
    def __init__(self):
        self._train()

    def _train(self):
        X = np.array(TRAINING_DATA)
        X_normal = np.array(NORMAL_BASELINE)
        self.classifier = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight="balanced"))
        ])
        self.classifier.fit(X, TRAINING_LABELS)
        self.anomaly_detector = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        self.anomaly_detector.fit(X_normal)

    def analyze(self, feature_vector, port_data):
        if not any(feature_vector):
            return {"risk_level": "NONE", "confidence": 100, "is_anomaly": False, "anomaly_score": 0, "explanation": ["No open ports detected. Host may be firewalled or offline."], "top_threats": []}

        X = np.array([feature_vector])
        risk_level = self.classifier.predict(X)[0]
        proba = self.classifier.predict_proba(X)[0]
        confidence = round(float(max(proba)) * 100, 1)
        is_anomaly = bool(self.anomaly_detector.predict(X)[0] == -1)
        anomaly_score = round(float(self.anomaly_detector.score_samples(X)[0]), 4)

        explanation = self._explain(feature_vector, risk_level, is_anomaly)
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        top_threats = sorted(port_data, key=lambda p: risk_order.get(p.get("known_risk", "UNKNOWN"), 4))[:5]

        return {
            "risk_level": risk_level,
            "confidence": confidence,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "explanation": explanation,
            "top_threats": top_threats,
        }

    def _explain(self, features, risk, is_anomaly):
        num_ports, has_critical, has_db, has_remote, has_legacy, risk_score = features
        explanations = [f"Found {num_ports} open port(s) with a total risk score of {risk_score}."]
        if has_critical:
            explanations.append("Critical services detected (RDP/SMB/VNC/Redis/MongoDB). These are common ransomware and exploitation vectors.")
        if has_db:
            explanations.append("Database ports are publicly exposed. Databases should never be directly internet-accessible.")
        if has_remote:
            explanations.append("Remote access services detected (SSH/RDP/Telnet/VNC). Ensure strong authentication and MFA.")
        if has_legacy:
            explanations.append("Legacy protocols found (FTP/Telnet/POP3/NetBIOS). These transmit data in plaintext.")
        if is_anomaly:
            explanations.append("ANOMALY DETECTED: This port combination is statistically unusual. Manual investigation recommended.")
        ctx = {
            "LOW": "Overall risk profile appears relatively safe for a public-facing server.",
            "MEDIUM": "Moderate attack surface. Harden exposed services and review firewall rules.",
            "HIGH": "High risk profile. Immediate remediation required on critical findings."
        }
        if risk in ctx:
            explanations.append(ctx[risk])
        return explanations
