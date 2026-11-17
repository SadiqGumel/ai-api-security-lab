# Phase 10: Adversarial AI API Defense & Self-Healing Gateway

## 1. Executive Summary
Phase 10 of the AI-Driven API Security Lab introduces an enterprise-grade defense layer designed to neutralize sophisticated adversarial evasion, distributed scraping swarms, and zero-symbol semantic business-logic exploits. Operating under a strict **$0.00 local testing budget**, this module integrates multi-model anomaly consensus, cross-session sequence entropy tracking, asynchronous local LLM semantic inspection (Ollama), and poison-resistant online concept-drift self-retraining.

---

## 2. Architecture & Core Components

* **`ensembleGraphDetector.py` (`api_gateway/ml/`)**
    * **Dual-Model Consensus:** Combines tree-based isolation (`IsolationForest`) and density-based outlier detection (`LocalOutlierFactor` with `novelty=True`) to eliminate single-model blind spots.
    * **Markov Transition Sequence Graph:** Tracks global client endpoint traversal paths and computes sliding-window Shannon entropy to instantly detect distributed scraping swarms and automated reconnaissance.

* **`semanticInspector.py` (`api_gateway/ml/`)**
    * **Local Ollama Integration:** Routes ambiguous gray-zone payloads asynchronously to local LLM instances (`llama3.2:1b`) for semantic business-logic abuse detection.
    * **Robust Heuristic Fallback:** Features built-in offline heuristics for negative parameter tampering (`quantity < 0`) and privilege escalation (`role: admin`) ensuring zero downtime during air-gapped testing.

* **`driftManager.py` (`api_gateway/ml/`)**
    * **Online Concept Drift Tracking:** Monitors sliding-window threat score averages to flag behavioral drift.
    * **Anti-Poisoning Ring Buffer:** Enforces strict cryptographic/sanitization rules—accepting samples into the training buffer *only* if the threat score is $< 0.20$ *and* the response code is HTTP 200, successfully blocking data-poisoning attacks.

* **`adaptiveRateLimiter.py` (`api_gateway/middleware/`)**
    * Unified gateway middleware enforcing dynamic token-bucket capacity penalties (80% penalty for high threats, 50% for medium) and returning rich telemetry headers (`X-Threat-Score`, `X-AI-Anomaly`, `X-Semantic-Verdict`, `X-Drift-Detected`).

---

## 3. Adversarial Test Harness & Verification

The defense suite is validated against a rigorous 4-vector adversarial test harness (`tests/test_adversarial_ai_defense.py`):

| Test Vector | Attack Technique | Defense Mechanism | Test Status |
| :--- | :--- | :--- | :--- |
| **Vector A** | Gaussian-Jittered Mimicry | Dual-model consensus (`IsolationForest` + `LOF`) | **PASSED** |
| **Vector B** | Distributed 50-IP BOLA Swarm | Markov chain sequence entropy tracking | **PASSED** |
| **Vector C** | Zero-Symbol Semantic Exploit | Asynchronous LLM / heuristic fallback logic | **PASSED** |
| **Vector D** | Data-Poisoning Attack | Anti-poisoning ring buffer validation | **PASSED** |

### Test Execution Output
```bash
$ PYTHONPATH=. python3 -m pytest tests/test_adversarial_ai_defense.py -v
platform linux -- Python 3.14.8, pytest-9.2.0, pluggy-1.7.0 -- /home/abubakar/ai-api-security-lab/venv/bin/python3
cachedir: .pytest_cache
rootdir: /home/abubakar/ai-api-security-lab
collected 4 items

tests/test_adversarial_ai_defense.py::test_vector_a_gaussian_mimicry PASSED
tests/test_adversarial_ai_defense.py::test_vector_b_distributed_bola_swarm PASSED
tests/test_adversarial_ai_defense.py::test_vector_c_zero_symbol_semantic_exploit PASSED
tests/test_adversarial_ai_defense.py::test_vector_d_data_poisoning_resilience PASSED
