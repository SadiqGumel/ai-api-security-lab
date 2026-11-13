import pytest
from api_gateway.middleware.adaptiveRateLimiter import AdaptiveRateLimiter

def test_low_and_slow_evasion_detection():
    """
    Verify that distributed/low-and-slow requests with anomalous features 
    are intercepted by the ML anomaly detector and adaptive rate limiter.
    """
    limiter = AdaptiveRateLimiter()
    client_ip = "203.0.113.88"

    # Simulate highly evasive credential stuffing payload with intense SQLi/XSS tokens & erratic delta
    evasive_req = {
        "frequency": 0.1,  
        "body": "UNION SELECT username, password, credit_card, ssn FROM users WHERE '1'='1' UNION SELECT 1,2,3,4-- <script>alert(1)</script>",
        "headers": {"User-Agent": "BotNet-Scanner/9.9", "X-Custom-Noise": "abc123xyz789!@#$"},
        "time_delta_ms": 25000.0
    }

    allowed, status_code, headers = limiter.check_request(client_ip, "auth", evasive_req)
    
    # The ML model should flag the anomaly and return 403/429
    assert allowed is False
    assert status_code in [403, 429]
    assert float(headers["X-Threat-Score"]) > 0.45
    assert headers["X-AI-Anomaly"] == "True"

def test_benign_traffic_flow():
    """Verify standard benign traffic passes unhindered."""
    limiter = AdaptiveRateLimiter()
    client_ip = "192.168.1.10"

    benign_req = {
        "frequency": 1.0,
        "body": "normal user login payload",
        "headers": {"User-Agent": "Mozilla/5.0"},
        "time_delta_ms": 800.0
    }

    allowed, status_code, headers = limiter.check_request(client_ip, "auth", benign_req)
    assert allowed is True
    assert status_code == 200
    assert float(headers["X-Threat-Score"]) < 0.7
