import asyncio
import numpy as np
from api_gateway.telemetry.kernelCorrelator import KernelSocketCorrelator
from api_gateway.ml.dpDefense import DifferentialPrivacyDefense
from api_gateway.deception.shadowHoneypot import StatefulShadowHoneypot
from arena.redBlueSelfPlay import RedBlueSelfPlayArena


def test_1_kernel_socket_spoof_attribution():
    correlator = KernelSocketCorrelator()
    fingerprints = set()
    spoof_flags = []

    for i in range(5):
        telemetry = correlator.extract_telemetry(
            peer_ip="10.10.10.50",
            peer_port=40000 + i,
            headers={"x-forwarded-for": f"203.0.113.{i}", "user-agent": f"SpoofAgent/{i}.0"},
            override_metrics=(18.4, 0.3, 10, 1460, 0),
        )
        fingerprints.add(telemetry.stack_fingerprint)
        spoof_flags.append(telemetry.spoof_detected)

    assert len(fingerprints) == 1
    assert spoof_flags[-1] is True


def test_2_differential_privacy_and_probing_detection():
    dp = DifferentialPrivacyDefense(epsilon=1.0, sensitivity=0.05)
    rng = np.random.default_rng(7)

    probing_detected = False
    for i in range(30):
        probe_vec = rng.uniform(-4.5, 4.5, size=5)
        detected, _ = dp.record_and_check_probing("attacker_fp_01", probe_vec)
        if detected:
            probing_detected = True

    assert probing_detected is True

    perturbed_scores = [dp.perturb_threat_score(0.75) for _ in range(20)]
    assert len(set(perturbed_scores)) > 5
    assert all(0.0 <= s <= 1.0 for s in perturbed_scores)


def test_3_stateful_shadow_honeypot_deception():
    honeypot = StatefulShadowHoneypot()

    async def run_attack_chain():
        r1 = await honeypot.engage_shadow_session(
            "fp_attacker_99", "GET", "/api/v1/admin/config", {}, tarpit_delay_ms=5.0
        )
        r2 = await honeypot.engage_shadow_session(
            "fp_attacker_99", "POST", "/api/v1/users/export", {"token": r1["canary_token"]}, tarpit_delay_ms=5.0
        )
        return r1, r2

    r1, r2 = asyncio.run(run_attack_chain())

    assert r1["status_code"] == 200
    assert r1["canary_token"].startswith("sk_live_canary_")
    assert r2["step_captured"] == 2

    chain = honeypot.get_attacker_chain("fp_attacker_99")
    assert len(chain) == 2
    assert chain[1]["payload"]["token"] == r1["canary_token"]


def test_4_red_vs_blue_500_round_self_play():
    arena = RedBlueSelfPlayArena()
    metrics = arena.run_tournament(total_rounds=500)

    assert metrics.rounds == 500
    assert metrics.shadow_captures > 250
    assert metrics.evasion_curve[-1] <= metrics.evasion_curve[0]
