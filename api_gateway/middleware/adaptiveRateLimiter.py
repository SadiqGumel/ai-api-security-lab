import time
import json
from typing import Dict, Tuple
from api_gateway.ml.ensembleGraphDetector import EnsembleGraphDetector
from api_gateway.ml.semanticInspector import SemanticPayloadInspector
from api_gateway.ml.driftManager import OnlineDriftManager

class AdaptiveRateLimiter:
    """
    Phase 10 Adaptive Rate Limiter incorporating Ensemble Graph Detection,
    Asynchronous Local Ollama Semantic Inspection, and Online Drift Management.
    """
    def __init__(self):
        self.detector = EnsembleGraphDetector()
        self.semantic_inspector = SemanticPayloadInspector()
        self.drift_manager = OnlineDriftManager()
        
        self.tiers = {
            "auth": {"capacity": 5, "window": 10},
            "api": {"capacity": 50, "window": 10}
        }
        self.client_buckets = {}

    def check_request(self, client_ip: str, tier: str, req_data: Dict) -> Tuple[bool, int, Dict]:
        current_time = time.time()
        
        # 1. Evaluate request through Ensemble Graph Detector
        threat_score, is_anomaly, telemetry = self.detector.evaluate_request(req_data)
        
        # 2. Semantic Payload Inspection for sensitive endpoints or gray-zone scores
        semantic_verdict = "BENIGN_SEMANTICS"
        endpoint = req_data.get("endpoint", "/api/resource")
        body = req_data.get("body", {})
        if isinstance(body, str):
            try:
                body = json.loads(body.replace("'", '"'))
            except Exception:
                body = {"raw": body}

        if threat_score <= 0.75 or endpoint in ["/api/checkout", "/api/transfer", "/api/admin"]:
            is_malicious_logic, sem_score, sem_reason = self.semantic_inspector.inspect_payload(endpoint, body)
            if is_malicious_logic or sem_score > 0.60:
                threat_score = max(threat_score, sem_score)
                is_anomaly = True
                semantic_verdict = f"MALICIOUS_LOGIC: {sem_reason}"

        # 3. Record observation for concept drift tracking
        feature_vector = [
            float(req_data.get("frequency", 1.0)),
            float(len(str(req_data.get("body", "")))),
            telemetry.get("seq_entropy", 0.0),
            float(req_data.get("time_delta_ms", 500.0)),
            telemetry.get("suspicious_ratio", 0.0)
        ]
        self.drift_manager.record_observation(threat_score, is_http_200=not is_anomaly, feature_vector=feature_vector)

        # 4. Adaptive Rate Limiting & Capacity Penalty
        tier_config = self.tiers.get(tier, self.tiers["api"])
        capacity = tier_config["capacity"]
        
        if threat_score > 0.70 or is_anomaly:
            capacity = int(capacity * 0.20)
        elif threat_score > 0.40:
            capacity = int(capacity * 0.50)

        if client_ip not in self.client_buckets:
            self.client_buckets[client_ip] = {"tokens": capacity, "last_update": current_time}
        
        bucket = self.client_buckets[client_ip]
        elapsed = current_time - bucket["last_update"]
        bucket["tokens"] = min(capacity, bucket["tokens"] + elapsed * (capacity / tier_config["window"]))
        bucket["last_update"] = current_time

        headers = {
            "X-Threat-Score": str(threat_score),
            "X-AI-Anomaly": str(is_anomaly),
            "X-Semantic-Verdict": semantic_verdict,
            "X-Drift-Detected": str(self.drift_manager.check_drift_detected())
        }

        if is_anomaly or threat_score > 0.75:
            return False, 403, headers

        if bucket["tokens"] < 1.0:
            return False, 429, headers

        bucket["tokens"] -= 1.0
        return True, 200, headers
