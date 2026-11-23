# Phase 11 Capstone: Autonomous Cyber Deception, Kernel-to-API Socket Attribution, Differentially Private ML & Multi-Agent Red-vs-Blue Self-Play

**Project:** AI-Driven API Security Lab (`ai-api-security-lab`)  
**Execution Environment:** Local Workstation / Kali Linux / Python 3.14.8 / NumPy / SQLite / Linux `ss` & `/proc` / Local Ollama (`llama3.2:1b`) / Pytest  
**Cost:** `$0.00` (Zero Cloud VMs, Zero Paid APIs)

---

## 1. Executive Summary

Phase 11 extends the AI-driven API security gateway with kernel-aware network telemetry, privacy-aware machine learning, deceptive honeypot routing, and adversarial Red-vs-Blue testing.

The architecture combines transport-layer TCP information with application-layer security signals to improve threat attribution beyond HTTP headers such as `X-Forwarded-For` and `User-Agent`.

High-confidence suspicious traffic can be directed into an isolated deception environment. The environment uses SQLite to record attacker interactions, canary credentials to identify unauthorized access attempts, and optional local Ollama integration for decoy responses.

The system also introduces a Red-vs-Blue self-play framework to evaluate how defensive detection responds to changing attack patterns.

**Implementation note:** The capabilities described below should be interpreted according to the actual code and test evidence available in the repository. Passing unit tests alone does not establish production readiness or formal privacy guarantees.

---

## 2. Mathematical and Architectural Design

### A. Kernel-to-API Socket Attribution

**Proposed module:** `api_gateway/telemetry/kernelCorrelator.py`

The telemetry component correlates application-level connection information with Linux TCP socket information.

Potential telemetry sources include:

- `ss -tin`
- `/proc/net/tcp`
- Peer IP address and port
- TCP retransmission information
- Congestion window (`cwnd`)
- Maximum Segment Size (`MSS`)
- Round-trip time (`RTT`)

The proposed TCP feature vector is:

$$
\mathbf{x}_{tcp} =
\begin{bmatrix}
RTT_{ms} \\
\sigma_{RTT}^{2} \\
cwnd \\
retrans + 5I(spoof\_detected)
\end{bmatrix}
$$

Where:

- $RTT_{ms}$ represents round-trip time.
- $\sigma_{RTT}^{2}$ represents RTT variance.
- $cwnd$ represents the TCP congestion window.
- $retrans$ represents retransmission information.
- $I(spoof\_detected)$ is an indicator variable.

**Security consideration:** TCP telemetry can improve correlation, but it cannot reliably identify a physical device or user by itself. NAT, proxies, container networking, and operating-system differences can affect attribution.

### B. Differentially Private ML and Boundary Probing Defense

**Proposed module:** `api_gateway/ml/dpDefense.py`

This component explores privacy-aware threat scoring and detection of systematic model probing.

#### 1. Feature-Space Grid Entropy

Normalized feature vectors are discretized into grid cells over a rolling observation window.

Shannon entropy is calculated as:

$$
H(C) = -\sum_c p(c)\log_2 p(c)
$$

Where $p(c)$ represents the observed probability of a feature vector occupying cell $c$.

High entropy and unusual cell dispersion may indicate systematic probing.

#### 2. Laplace Output Perturbation

The proposed threat-score perturbation is:

$$
\tilde{T} =
clip\left(
T + Lap\left(\frac{\Delta f}{\epsilon}\right),
0,1
\right)
$$

Where:

- $T$ is the original threat score.
- $\Delta f$ is the sensitivity.
- $\epsilon$ is the privacy budget.

**Important:** Adding Laplace noise does not automatically establish differential privacy. A formal guarantee requires a defined neighboring-dataset relationship, bounded sensitivity, correct noise calibration, and privacy-budget accounting.

#### 3. Gaussian Noise for Model Updates

The proposed Gaussian noise scale is:

$$
\sigma =
\frac{\Delta f\sqrt{2\ln(1.25/\delta)}}{\epsilon N}
$$

This expression requires carefully defined clipping, sampling, and sensitivity assumptions before it can be treated as a valid differential privacy mechanism.

### C. Stateful LLM-Backed Deception Shadow Routing

**Proposed module:** `api_gateway/deception/shadowHoneypot.py`

The deception component is designed to isolate suspicious requests from legitimate application workflows.

Proposed capabilities:

- Stateful SQLite deception environment.
- `canary_tokens` table.
- `captured_ttps` table.
- Local Ollama integration using `llama3.2:1b`.
- Deterministic fallback responses.
- Progressive response delays.
- Unique synthetic canary credentials.
- Multi-step interaction logging.

Illustrative canary format:

```text
sk_live_canary_<hex>
```

The proposed routing threshold is:

$$
T_{score} > 0.75
$$

Suspicious traffic above the threshold can be redirected to a controlled deception environment.

**Security consideration:** Canary credentials must be synthetic, nonfunctional, and isolated from production secrets. The deception service should not expose real databases or sensitive infrastructure.

### D. Autonomous Red-vs-Blue Self-Play Arena

**Proposed module:** `arena/redBlueSelfPlay.py`

The self-play framework evaluates defensive detection against changing attack patterns.

**Red Agent**

The Red Agent generates controlled test variations involving:

- HTTP header changes.
- User-Agent rotation.
- Request timing jitter.
- SQL injection test strings.
- Negative quantity inputs.
- Privilege escalation test cases.
- Obfuscated payload patterns.

**Blue Agent**

The Blue Agent evaluates incoming test cases using:

- Network telemetry.
- Threat scoring.
- Detection rules.
- Adaptive defensive weights.
- Previously observed attack patterns.

The objective is to measure whether defensive detection remains effective as attack simulations evolve.

---

## 3. Empirical Verification and Testing

### A. Pytest Execution

Run the following command from the project root:

```bash
PYTHONPATH=. python3 -m pytest tests/test_phase11_autonomous_defense.py -v
```

### B. Test Coverage

The proposed Phase 11 test suite covers four areas:

| Test | Description |
|---|---|
| Test 1 | Kernel socket spoof attribution |
| Test 2 | Differential privacy and probing detection |
| Test 3 | Stateful shadow honeypot deception |
| Test 4 | Red-vs-Blue 500-round self-play |

### C. Actual Test Results

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
```

### D. Recommended Performance Metrics

For a stronger evaluation, measure:

| Metric | Purpose |
|---|---|
| Detection Accuracy | Measures correct classifications |
| Precision | Measures the proportion of detected attacks that are genuine |
| Recall | Measures the proportion of attacks successfully detected |
| False Positive Rate | Measures legitimate traffic incorrectly flagged |
| F1-Score | Balances precision and recall |
| Detection Latency | Measures time required to identify suspicious traffic |
| CPU and Memory Usage | Measures computational overhead |
| Canary Detection Rate | Measures detection of unauthorized canary interactions |
| Red-vs-Blue Win Rate | Measures defensive performance across simulation rounds |

---

## 4. Security and Reliability Considerations

The Phase 11 architecture should account for:

1. **Isolation:** Deception infrastructure must remain separated from production systems.
2. **Privacy:** Threat telemetry should avoid collecting unnecessary personal information.
3. **Network reliability:** Linux socket telemetry may be unavailable or incomplete in restricted environments.
4. **LLM reliability:** Local model responses must have deterministic fallbacks.
5. **False positives:** Threat thresholds should be evaluated against legitimate traffic.
6. **Privacy accounting:** Differential privacy claims require mathematically verified mechanisms.
7. **Reproducibility:** Experiments should document datasets, configurations, random seeds, and software versions.

---


