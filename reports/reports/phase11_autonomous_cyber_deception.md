# Phase 11 Capstone: Autonomous Cyber Deception, Kernel-to-API Socket Attribution, Differentially Private ML & Multi-Agent Red-vs-Blue Self-Play

**Project:** AI-Driven API Security Lab (`ai-api-security-lab`)  
**Execution Environment:** 100% Local Workstation / Kali Linux / Python 3.14.8 / NumPy / SQLite / Linux `ss` & `/proc` / Local Ollama (`llama3.2:1b`) / Pytest  
**Cost:** `$0.00` (Zero Cloud VMs, Zero Paid APIs)  

---

## 1. Executive Summary
Phase 11 upgrades the API security gateway from a passive Layer-7 filter into an active, kernel-aware deception and self-healing defense organism. Rather than tipping off adversaries with predictable `403`/`429` rejections or relying solely on spoofable HTTP headers (`X-Forwarded-For`, `User-Agent`), the Phase 11 architecture fuses transport-layer TCP telemetry, enforces $\epsilon$-differential privacy against model extraction and boundary probing, silently shadow-routes high-confidence attackers (`T_score > 0.75`) into a stateful deception twin with watermarked canary tokens, and validates resilience across a 500-round co-evolutionary Red-vs-Blue self-play tournament.

---

## 2. Mathematical & Architectural Design

### A. Kernel-to-API Socket Attribution (`api_gateway/telemetry/kernelCorrelator.py`)
Incoming connections (`peer_ip:peer_port`) are correlated against Linux socket telemetry (`ss -tin` / `/proc/net/tcp`) to extract:
- Round-trip time ($\text{RTT}_{\text{ms}}$) and empirical RTT variance ($\sigma_{\text{RTT}}^2$)
- Congestion window ($\text{cwnd}$), Maximum Segment Size ($\text{MSS}$), and retransmission counts
- Transport stack fingerprint hash linking sessions from the same underlying TCP/IP stack even when `X-Forwarded-For` and `User-Agent` headers rotate

Transport feature vector fused into ML scoring:
$$\mathbf{x}_{\text{tcp}} = \begin{bmatrix} \text{RTT}_{\text{ms}} & \sigma_{\text{RTT}}^2 & \text{cwnd} & \text{retrans} + 5 \cdot \mathbb{I}(\text{spoof\_detected}) \end{bmatrix}^T$$

### B. Differentially Private ML & Boundary Probing Defense (`api_gateway/ml/dpDefense.py`)
To defend against model extraction, boundary probing, and membership inference:
1. **Feature-Space Grid Entropy:** Discretizes normalized feature vectors into grid cells over a rolling client window and computes Shannon entropy:
   $$H(C) = -\sum_{c} p(c) \log_2 p(c)$$
   High cell dispersion paired with high entropy flags systematic grid-search or binary-search boundary probing.
2. **Calibrated Laplace Output Perturbation ($\epsilon$-DP):** Adds Laplace noise scaled by sensitivity $\Delta f$ and privacy budget $\epsilon$ to threat scores:
   $$\tilde{T} = \text{clip}\!\left(T + \text{Lap}\!\left(\frac{\Delta f}{\epsilon}\right),\, 0,\, 1\right)$$
3. **Differentially Private Centroid Updates:** Applies calibrated Gaussian noise to clean sample means during online drift updates:
   $$\sigma = \frac{\Delta f \sqrt{2 \ln(1.25 / \delta)}}{\epsilon \cdot N}$$

### C. Stateful LLM-Backed Deception Shadow-Routing (`api_gateway/deception/shadowHoneypot.py`)
For high-confidence adversaries (`T_score > 0.75`):
- Silently routes traffic to a stateful in-memory SQLite deception twin (`canary_tokens` and `captured_ttps` tables) paired with local Ollama (`llama3.2:1b`) decoy generation and deterministic fallback templates.
- Applies progressive tarpit latency scaling with exploit step depth while presenting a plausible `200` response containing a unique watermarked canary credential (`sk_live_canary_<hex>`).
- Tracks full multi-step attacker chains (`step_num`, `method`, `endpoint`, `payload`, `canary_issued`) for attribution and TTP capture.

### D. Autonomous Red-vs-Blue Self-Play Arena (`arena/redBlueSelfPlay.py`)
- **Red Agent:** Mutates `X-Forwarded-For`, `User-Agent`, inter-arrival timing jitter, and obfuscated attack payloads (`UNION/**/SELECT`, `' OR 1=1 --`, negative quantities, privilege escalation, JNDI strings) to minimize `T_score`.
- **Blue Agent:** Evaluates incoming mutations using kernel socket attribution, DP-perturbed threat scoring, and adaptive weight updates (`blue_weights`) plus learned obfuscation signatures.

---

## 3. Empirical Verification & Tournament Results

### A. Pytest Execution Transcript
```text
$ PYTHONPATH=. python3 -m pytest tests/test_phase11_autonomous_defense.py -v
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/abubakar
plugins: anyio-4.12.1
collected 4 items

tests/test_phase11_autonomous_defense.py::test_1_kernel_socket_spoof_attribution PASSED
tests/test_phase11_autonomous_defense.py::test_2_differential_privacy_and_probing_detection PASSED
tests/test_phase11_autonomous_defense.py::test_3_stateful_shadow_honeypot_deception PASSED
tests/test_phase11_autonomous_defense.py::test_4_red_vs_blue_500_round_self_play PASSED

============================== 4 passed in 1.27s ===============================


# Phase 11 Capstone: Autonomous Cyber Deception, Kernel-to-API Socket Attribution, Differentially Private ML & Multi-Agent Red-vs-Blue Self-Play

**Project:** AI-Driven API Security Lab (`ai-api-security-lab`)  
**Execution Environment:** 100% Local Workstation / Kali Linux / Python 3.14.8 / NumPy / SQLite / Linux `ss` & `/proc` / Local Ollama (`llama3.2:1b`) / Pytest  
**Cost:** `$0.00` (Zero Cloud VMs, Zero Paid APIs)  

---

## 1. Executive Summary
Phase 11 upgrades the API security gateway from a passive Layer-7 filter into an active, kernel-aware deception and self-healing defense organism. Rather than tipping off adversaries with predictable `403`/`429` rejections or relying solely on spoofable HTTP headers (`X-Forwarded-For`, `User-Agent`), the Phase 11 architecture fuses transport-layer TCP telemetry, enforces $\epsilon$-differential privacy against model extraction and boundary probing, silently shadow-routes high-confidence attackers (`T_score > 0.75`) into a stateful deception twin with watermarked canary tokens, and validates resilience across a 500-round co-evolutionary Red-vs-Blue self-play tournament.

---

## 2. Mathematical & Architectural Design

### A. Kernel-to-API Socket Attribution (`api_gateway/telemetry/kernelCorrelator.py`)
Incoming connections (`peer_ip:peer_port`) are correlated against Linux socket telemetry (`ss -tin` / `/proc/net/tcp`) to extract:
- Round-trip time ($\text{RTT}_{\text{ms}}$) and empirical RTT variance ($\sigma_{\text{RTT}}^2$)
- Congestion window ($\text{cwnd}$), Maximum Segment Size ($\text{MSS}$), and retransmission counts
- Transport stack fingerprint hash linking sessions from the same underlying TCP/IP stack even when `X-Forwarded-For` and `User-Agent` headers rotate

Transport feature vector fused into ML scoring:
- `x_tcp = [RTT_ms, sigma_RTT^2, cwnd, retrans + 5 * I(spoof_detected)]^T`

### B. Differentially Private ML & Boundary Probing Defense (`api_gateway/ml/dpDefense.py`)
To defend against model extraction, boundary probing, and membership inference:
1. **Feature-Space Grid Entropy:** Discretizes normalized feature vectors into grid cells over a rolling client window and computes Shannon entropy:
   - `H(C) = -sum_c p(c) * log2(p(c))`
   - High cell dispersion paired with high entropy flags systematic grid-search or binary-search boundary probing.
2. **Calibrated Laplace Output Perturbation ($\epsilon$-DP):** Adds Laplace noise scaled by sensitivity $\Delta f$ and privacy budget $\epsilon$ to threat scores:
   - `T_tilde = clip(T + Laplace(scale = delta_f / epsilon), 0.0, 1.0)`
3. **Differentially Private Centroid Updates:** Applies calibrated Gaussian noise to clean sample means during online drift updates:
   - `sigma = (delta_f * sqrt(2 * ln(1.25 / delta))) / (epsilon * N)`

### C. Stateful LLM-Backed Deception Shadow-Routing (`api_gateway/deception/shadowHoneypot.py`)
For high-confidence adversaries (`T_score > 0.75`):
- Silently routes traffic to a stateful in-memory SQLite deception twin (`canary_tokens` and `captured_ttps` tables) paired with local Ollama (`llama3.2:1b`) decoy generation and deterministic fallback templates.
- Applies progressive tarpit latency scaling with exploit step depth while presenting a plausible `200` response containing a unique watermarked canary credential (`sk_live_canary_<hex>`).
- Tracks full multi-step attacker chains (`step_num`, `method`, `endpoint`, `payload`, `canary_issued`) for attribution and TTP capture.

### D. Autonomous Red-vs-Blue Self-Play Arena (`arena/redBlueSelfPlay.py`)
- **Red Agent:** Mutates `X-Forwarded-For`, `User-Agent`, inter-arrival timing jitter, and obfuscated attack payloads (`UNION/**/SELECT`, `' OR 1=1 --`, negative quantities, privilege escalation, JNDI strings) to minimize `T_score`.
- **Blue Agent:** Evaluates incoming mutations using kernel socket attribution, DP-perturbed threat scoring, and adaptive weight updates (`blue_weights`) plus learned obfuscation signatures.

---

## 3. Empirical Verification & Tournament Results

### A. Pytest Execution Transcript
```text
$ PYTHONPATH=. python3 -m pytest tests/test_phase11_autonomous_defense.py -v
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/abubakar
plugins: anyio-4.12.1
collected 4 items

tests/test_phase11_autonomous_defense.py::test_1_kernel_socket_spoof_attribution PASSED
tests/test_phase11_autonomous_defense.py::test_2_differential_privacy_and_probing_detection PASSED
tests/test_phase11_autonomous_defense.py::test_3_stateful_shadow_honeypot_deception PASSED
tests/test_phase11_autonomous_defense.py::test_4_red_vs_blue_500_round_self_play PASSED

============================== 4 passed in 1.27s ===============================
