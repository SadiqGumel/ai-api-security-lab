import math
from collections import Counter, deque
from typing import Dict, Tuple
import numpy as np


class DifferentialPrivacyDefense:
    def __init__(self, epsilon: float = 1.2, sensitivity: float = 0.08, window_size: int = 100):
        self.epsilon = epsilon
        self.sensitivity = sensitivity
        self.window_size = window_size
        self._client_cells: Dict[str, deque] = {}
        self._rng = np.random.default_rng(seed=42)

    def _quantize_cell(self, features: np.ndarray, bins: int = 10) -> Tuple[int, ...]:
        clipped = np.clip(features, -5.0, 5.0)
        scaled = ((clipped + 5.0) / 10.0 * bins).astype(int)
        return tuple(scaled.tolist())

    def record_and_check_probing(self, client_key: str, features: np.ndarray) -> Tuple[bool, float]:
        history = self._client_cells.setdefault(client_key, deque(maxlen=self.window_size))
        cell = self._quantize_cell(features)
        history.append(cell)

        if len(history) < 15:
            return False, 0.0

        counts = Counter(history)
        total = len(history)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        unique_ratio = len(counts) / total

        is_probing = unique_ratio > 0.80 and entropy > 3.6
        return is_probing, round(entropy, 4)

    def perturb_threat_score(self, raw_score: float) -> float:
        scale = self.sensitivity / max(self.epsilon, 1e-4)
        noise = float(self._rng.laplace(loc=0.0, scale=scale))
        return round(float(np.clip(raw_score + noise, 0.0, 1.0)), 4)

    def dp_centroid_update(self, clean_samples: np.ndarray) -> np.ndarray:
        if len(clean_samples) == 0:
            return np.array([])
        raw_mean = np.mean(clean_samples, axis=0)
        sigma = (self.sensitivity * math.sqrt(2 * math.log(1.25 / 1e-5))) / (
            self.epsilon * len(clean_samples)
        )
        noise = self._rng.normal(loc=0.0, scale=sigma, size=raw_mean.shape)
        return raw_mean + noise
