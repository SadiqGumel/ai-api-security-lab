# Phase 9: AI-Powered API Threat Intelligence & Adaptive Anomaly Classification
**Project:** AI API Security Lab (`ai-api-security-lab`)  
**Author:** Sadiq Gumel  
**Status:** Completed & Verified  

---

## 1. Executive Summary
Modern API endpoints are increasingly targeted by sophisticated, low-and-slow attacks, credential stuffing, and evasive payload randomization that bypass static signature-matching and rigid threshold-based rate limiters. This report details the architecture, implementation, and empirical validation of **Phase 9**, introducing an AI-powered threat intelligence layer combining an unsupervised Machine Learning anomaly detector (`IsolationForest`) with heuristic feature extraction and adaptive token-bucket rate limiting.

---

## 2. Architecture & ML Feature Extraction Pipeline
The threat intelligence gateway intercepts incoming HTTP requests and extracts a multi-dimensional numerical feature vector before routing traffic to backend services:
* **Request Frequency (`freq`):** Evaluates request velocity over sliding time windows.
* **Payload Size (`payload_size`):** Quantifies request body and parameter volume.
* **Header Entropy (`header_entropy`):** Computes Shannon entropy across request headers to detect obfuscated user agents or injected header noise.
* **Time Delta (`time_delta_ms`):** Measures temporal gaps between consecutive client interactions to spot low-and-slow automation.
* **Suspicious Token Ratio (`suspicious_ratio`):** Calculates the density of SQL injection tokens (`'`, `"`, `--`, `UNION`, `SELECT`), XSS scripts (`<script>`), and command injection markers.

---

## 3. Anomaly Detection Model Specification
* **Algorithm:** Scikit-Learn `IsolationForest` initialized with 100 estimators (`n_estimators=100`), a contamination factor of `0.05`, and a fixed random state for reproducibility.
* **Scoring & Normalization:** Raw decision function scores are normalized via a logistic sigmoid transformation to yield a continuous threat score between `0.0` (benign) and `1.0` (severe anomaly).
* **Heuristic Guardrails:** Direct threshold overrides are implemented to instantly flag payloads exceeding a suspicious token ratio (`> 0.05`), ensuring high-confidence injection attempts are intercepted regardless of isolation depth.

---

## 4. API Gateway Integration (`adaptiveRateLimiter.py`)
The adaptive middleware dynamically scales token-bucket capacities based on real-time ML threat scores:
* **Threat Score > 0.7:** Applies an aggressive capacity penalty, reducing tier request limits by 80% and triggering HTTP 403/429 responses.
* **Threat Score > 0.4:** Applies a moderate capacity penalty (50% reduction).
* **RFC Telemetry Headers:** Injects standard security and diagnostics headers (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `X-Threat-Score`, `X-AI-Anomaly`) into all responses.

---

## 5. Test Execution & Attack Mitigation Validation
The test suite (`tests/test_ai_evasion.py`) verifies both evasive attack interception and benign traffic pass-through.

### Execution Transcript:
```bash
platform linux -- Python 3.14.8, pytest-9.2.0, pluggy-1.7.0 -- /home/abubakar/ai-api-security-lab/venv/bin/python3
cachedir: .pytest_cache
rootdir: /home/abubakar/ai-api-security-lab
collected 2 items

tests/test_ai_evasion.py::test_low_and_slow_evasion_detection PASSED
tests/test_ai_evasion.py::test_benign_traffic_flow PASSED

============================== 2 passed in 3.48s ===============================
