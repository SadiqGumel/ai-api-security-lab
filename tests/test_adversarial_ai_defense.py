import pytest
import numpy as np
from api_gateway.middleware.adaptiveRateLimiter import AdaptiveRateLimiter

def test_vector_a_gaussian_mimicry():
    """Vector A: Gaussian-Jittered Mimicry Attack bypassing single IsolationForest."""
    limiter = AdaptiveRateLimiter()
    client_ip = "192.168.1.50"
    
    # Mimicry payload with normal frequency but anomalous feature correlation
    mimicry_req = {
        "frequency": 1.0,
        "body": "{\"user_id\": 999, \"action\": \"dump_database\"}",
        "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"},
        "time_delta_ms": np.random.normal(800, 50),
        "endpoint": "/api/export"
    }
    allowed, status_code, headers = limiter.check_request(client_ip, "api", mimicry_req)
    # Ensemble dual-model consensus should catch the feature correlation mismatch
    assert float(headers["X-Threat-Score"]) > 0.40

def test_vector_b_distributed_bola_swarm():
    """Vector B: Distributed 50-IP BOLA Scraping Swarm."""
    limiter = AdaptiveRateLimiter()
    
    # Simulate requests across 50 distinct IPs hitting sequential object IDs
    for i in range(1, 15):
        ip = f"203.0.113.{i}"
        req = {
            "frequency": 1.0,
            "body": f"{{\"item_id\": {i}}}",
            "endpoint": f"/api/items/{i}",
            "prev_endpoint": "/api/items" if i == 1 else f"/api/items/{i-1}"
        }
        allowed, status_code, headers = limiter.check_request(ip, "api", req)
    
    # Final request in sequence should spike entropy and trigger defense
    final_req = {
        "frequency": 1.0,
        "body": "{\"item_id\": 15}",
        "endpoint": "/api/items/15",
        "prev_endpoint": "/api/items/14"
    }
    allowed, status_code, headers = limiter.check_request("203.0.113.15", "api", final_req)
    assert float(headers["X-Threat-Score"]) > 0.50 or headers["X-AI-Anomaly"] == "True"

def test_vector_c_zero_symbol_semantic_exploit():
    """Vector C: Zero-Symbol Semantic Business-Logic Exploit (Negative Quantity / Admin Role)."""
    limiter = AdaptiveRateLimiter()
    client_ip = "192.168.1.88"
    
    exploit_req = {
        "frequency": 1.0,
        "body": {"item_id": 4, "quantity": -50, "role": "admin"},
        "endpoint": "/api/checkout",
        "prev_endpoint": "/api/basket"
    }
    allowed, status_code, headers = limiter.check_request(client_ip, "api", exploit_req)
    assert allowed is False
    assert status_code == 403
    assert "MALICIOUS_LOGIC" in headers["X-Semantic-Verdict"]

def test_vector_d_data_poisoning_resilience():
    """Vector D: Data-Poisoning & Drift Resilience Test."""
    limiter = AdaptiveRateLimiter()
    
    initial_buffer_size = len(limiter.drift_manager.clean_buffer)
    
    # Flood gateway with malicious / flagged traffic (threat score > 0.20 or status != 200)
    for i in range(20):
        malicious_req = {
            "frequency": 5.0,
            "body": "UNION SELECT password FROM users --",
            "endpoint": "/login"
        }
        limiter.check_request("10.0.0.99", "auth", malicious_req)
    
    # Verify ring buffer strictly rejected poisoned samples
    final_buffer_size = len(limiter.drift_manager.clean_buffer)
    assert final_buffer_size == initial_buffer_size
