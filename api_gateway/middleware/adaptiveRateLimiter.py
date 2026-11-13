import time
from collections import defaultdict
from typing import Tuple, Dict
from api_gateway.ml.anomalyDetector import AIAnomalyDetector

class AdaptiveRateLimiter:
    """
    Adaptive rate limiter combining sliding-window token buckets with 
    real-time ML anomaly threat scores.
    """
    def __init__(self):
        self.request_windows = defaultdict(list)
        self.ml_detector = AIAnomalyDetector()
        
        # Base tiered limits: (max_requests, window_seconds)
        self.base_tiers = {
            "auth": (5, 10),       # 5 req / 10s
            "standard": (100, 60)  # 100 req / min
        }

    def check_request(self, identifier: str, tier: str, req_data: Dict) -> Tuple[bool, int, Dict]:
        """
        Evaluates request through ML threat scorer and adaptive token bucket.
        Returns: (is_allowed, http_status, telemetry_headers)
        """
        # 1. Evaluate request via ML Anomaly Detector
        threat_score, is_anomaly = self.ml_detector.evaluate_request(req_data)
        
        max_requests, window_seconds = self.base_tiers.get(tier, self.base_tiers["standard"])

        # 2. Adaptive Throttling: Scale down capacity if threat score is high
        if threat_score > 0.7:
            max_requests = max(1, int(max_requests * 0.2))
        elif threat_score > 0.4:
            max_requests = max(1, int(max_requests * 0.5))

        now = time.time()
        key = f"{tier}:{identifier}"

        # Sliding window pruning
        window_start = now - window_seconds
        timestamps = self.request_windows[key]
        self.request_windows[key] = [t for t in timestamps if t > window_start]

        current_count = len(self.request_windows[key])
        remaining = max(0, max_requests - current_count - 1)
        reset_time = int(now + window_seconds)

        headers = {
            "RateLimit-Limit": str(max_requests),
            "RateLimit-Remaining": str(remaining),
            "RateLimit-Reset": str(reset_time),
            "X-Threat-Score": str(threat_score),
            "X-AI-Anomaly": str(is_anomaly)
        }

        if current_count >= max_requests or is_anomaly:
            headers["Retry-After"] = str(window_seconds)
            status_code = 429 if current_count >= max_requests else 403
            return False, status_code, headers

        # Record valid request timestamp
        self.request_windows[key].append(now)
        return True, 200, headers
