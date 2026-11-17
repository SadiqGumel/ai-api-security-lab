import numpy as np
from collections import deque
from typing import List, Dict, Tuple

class OnlineDriftManager:
    """
    Manages online concept drift detection using a sliding window threat score average
    and an anti-poisoning ring buffer to safely retrain and hot-swap models without downtime.
    """
    def __init__(self, window_size: int = 50, drift_threshold: float = 0.45):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        # Sliding window for recent threat scores
        self.recent_threats = deque(maxlen=window_size)
        
        # Poison-resistant ring buffer for verified clean baseline samples
        self.clean_buffer = deque(maxlen=500)

    def record_observation(self, threat_score: float, is_http_200: bool, feature_vector: List[float]):
        self.recent_threats.append(threat_score)
        
        # Anti-poisoning rule: Only store samples if threat score is very low AND response was HTTP 200
        if threat_score < 0.20 and is_http_200:
            self.clean_buffer.append(feature_vector)

    def check_drift_detected(self) -> bool:
        if len(self.recent_threats) < self.window_size:
            return False
        
        avg_threat = sum(self.recent_threats) / len(self.recent_threats)
        return avg_threat > self.drift_threshold

    def get_retraining_batch(self) -> np.ndarray:
        """Returns accumulated clean feature vectors for retraining."""
        if not self.clean_buffer:
            return np.array([])
        return np.array(list(self.clean_buffer))
