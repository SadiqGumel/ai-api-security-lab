import numpy as np
import math
from sklearn.ensemble import IsolationForest
from typing import Dict, Tuple

class AIAnomalyDetector:
    """
    Local ML-based anomaly detector using Isolation Forest combined with heuristic 
    guardrails to evaluate incoming request feature vectors and compute dynamic threat scores.
    """
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.is_trained = False
        self._bootstrap_baseline()

    def _extract_features(self, req_data: Dict) -> Tuple[np.ndarray, float]:
        freq = float(req_data.get("frequency", 1.0))
        payload_str = str(req_data.get("body", ""))
        payload_size = float(len(payload_str))
        
        headers = req_data.get("headers", {})
        header_str = "".join(f"{k}:{v}" for k, v in headers.items())
        header_entropy = self._calculate_entropy(header_str) if header_str else 0.0
        
        time_delta = float(req_data.get("time_delta_ms", 500.0))
        
        payload_text = payload_str + str(req_data.get("query_string", ""))
        suspicious_tokens = ["'", "\"", ";", "--", "<", ">", "UNION", "SELECT", "script"]
        suspicious_chars = sum(payload_text.upper().count(token) for token in suspicious_tokens)
        suspicious_ratio = float(suspicious_chars) / max(1.0, len(payload_text))

        features = np.array([[freq, payload_size, header_entropy, time_delta, suspicious_ratio]])
        return features, suspicious_ratio

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = float(data.count(x)) / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def _bootstrap_baseline(self):
        normal_baseline = np.array([
            [1.2, 120.0, 3.5, 800.0, 0.0],
            [0.8, 250.0, 3.8, 1200.0, 0.0],
            [2.0, 80.0, 3.2, 450.0, 0.0],
            [0.5, 500.0, 4.1, 2000.0, 0.0],
            [1.5, 150.0, 3.6, 600.0, 0.0]
        ] * 20)
        self.model.fit(normal_baseline)
        self.is_trained = True

    def evaluate_request(self, req_data: Dict) -> Tuple[float, bool]:
        features, suspicious_ratio = self._extract_features(req_data)
        
        raw_score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]

        normalized_threat = 1.0 / (1.0 + math.exp(raw_score * 5.0))
        
        # Boost threat score if suspicious injection tokens/ratios are detected
        if suspicious_ratio > 0.05:
            normalized_threat = max(normalized_threat, 0.85)

        is_anomaly = (prediction == -1) or (normalized_threat > 0.75) or (suspicious_ratio > 0.05)
        return float(round(normalized_threat, 4)), bool(is_anomaly)
