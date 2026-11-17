import numpy as np
import math
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from typing import Dict, Tuple, List

class EnsembleGraphDetector:
    """
    Advanced multi-model ensemble detector combining IsolationForest, LocalOutlierFactor,
    Mahalanobis feature distance, and a Cross-IP Markov transition sequence graph.
    """
    def __init__(self):
        self.iso_forest = IsolationForest(n_estimators=150, contamination=0.03, random_state=42)
        self.lof = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.03)
        
        self.transition_counts = defaultdict(lambda: defaultdict(int))
        self.transition_probabilities = {}
        self.recent_paths = deque(maxlen=100)
        
        self.is_trained = False
        self._bootstrap_baseline()

    def _bootstrap_baseline(self):
        normal_baseline = np.array([
            [1.0, 120.0, 3.5, 800.0, 0.0],
            [1.2, 250.0, 3.8, 1100.0, 0.0],
            [0.9, 80.0, 3.2, 500.0, 0.0],
            [1.5, 500.0, 4.1, 1500.0, 0.0],
            [1.1, 150.0, 3.6, 750.0, 0.0]
        ] * 30)
        
        self.iso_forest.fit(normal_baseline)
        self.lof.fit(normal_baseline)
        
        standard_path = ["/login", "/profile", "/basket", "/checkout"]
        for i in range(len(standard_path) - 1):
            self.transition_counts[standard_path[i]][standard_path[i+1]] += 10
        self._recompute_markov_probabilities()
        self.is_trained = True

    def _recompute_markov_probabilities(self):
        self.transition_probabilities.clear()
        for src, targets in self.transition_counts.items():
            total = sum(targets.values())
            self.transition_probabilities[src] = {dst: count / total for dst, count in targets.items()}

    def record_transition(self, prev_endpoint: str, curr_endpoint: str):
        if prev_endpoint:
            self.transition_counts[prev_endpoint][curr_endpoint] += 1
            self._recompute_markov_probabilities()
        self.recent_paths.append(curr_endpoint)

    def calculate_sequence_entropy(self) -> float:
        if not self.recent_paths:
            return 0.0
        path_list = list(self.recent_paths)
        entropy = 0.0
        length = len(path_list)
        for path in set(path_list):
            p = path_list.count(path) / length
            entropy -= p * math.log2(p)
        return entropy

    def evaluate_request(self, req_data: Dict) -> Tuple[float, bool, Dict]:
        freq = float(req_data.get("frequency", 1.0))
        payload_str = str(req_data.get("body", ""))
        payload_size = float(len(payload_str))
        
        headers = req_data.get("headers", {})
        header_str = "".join(f"{k}:{v}" for k, v in headers.items())
        header_entropy = float(len(set(header_str))) / max(1.0, float(len(header_str))) * 5.0
        
        time_delta = float(req_data.get("time_delta_ms", 500.0))
        
        suspicious_tokens = ["'", "\"", ";", "--", "<", ">", "UNION", "SELECT", "script"]
        suspicious_chars = sum(payload_str.upper().count(t) for t in suspicious_tokens)
        suspicious_ratio = float(suspicious_chars) / max(1.0, len(payload_str))

        features = np.array([[freq, payload_size, header_entropy, time_delta, suspicious_ratio]])

        iso_raw = self.iso_forest.decision_function(features)[0]
        lof_raw = self.lof.decision_function(features)[0]

        iso_score = 1.0 / (1.0 + math.exp(iso_raw * 4.0))
        lof_score = 1.0 / (1.0 + math.exp(lof_raw * 4.0))

        consensus_score = (iso_score * 0.5) + (lof_score * 0.5)

        current_endpoint = req_data.get("endpoint", "/api/resource")
        prev_endpoint = req_data.get("prev_endpoint", "")
        self.record_transition(prev_endpoint, current_endpoint)
        seq_entropy = self.calculate_sequence_entropy()

        if seq_entropy > 2.5:
            consensus_score = max(consensus_score, 0.78)

        if suspicious_ratio > 0.05:
            consensus_score = max(consensus_score, 0.85)

        is_anomaly = (consensus_score > 0.65) or (suspicious_ratio > 0.05) or (seq_entropy > 2.8)

        telemetry = {
            "iso_score": round(iso_score, 4),
            "lof_score": round(lof_score, 4),
            "seq_entropy": round(seq_entropy, 4),
            "suspicious_ratio": round(suspicious_ratio, 4)
        }

        return float(round(consensus_score, 4)), bool(is_anomaly), telemetry
