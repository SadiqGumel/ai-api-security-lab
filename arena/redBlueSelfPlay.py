import random
from dataclasses import dataclass, field
from typing import Dict, List
import numpy as np

from api_gateway.telemetry.kernelCorrelator import KernelSocketCorrelator
from api_gateway.ml.dpDefense import DifferentialPrivacyDefense
from api_gateway.deception.shadowHoneypot import StatefulShadowHoneypot


@dataclass
class TournamentMetrics:
    rounds: int = 0
    evasions: int = 0
    shadow_captures: int = 0
    blocked: int = 0
    evasion_curve: List[float] = field(default_factory=list)
    captured_signatures: List[str] = field(default_factory=list)


class RedBlueSelfPlayArena:
    def __init__(self):
        self.correlator = KernelSocketCorrelator()
        self.dp = DifferentialPrivacyDefense(epsilon=1.5, sensitivity=0.05)
        self.honeypot = StatefulShadowHoneypot()
        self.rng = random.Random(1337)

        self.blue_weights = np.array([0.55, 0.25, 0.20], dtype=np.float64)
        self.learned_obfuscations = set()

    def _mutate_red_attack(self, generation: int, best_genome: Dict) -> Dict:
        genome = dict(best_genome)
        mutation_type = self.rng.choice(["header_spoof", "timing_jitter", "payload_obfuscate"])

        if mutation_type == "header_spoof":
            genome["xff"] = f"10.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
            genome["ua"] = f"Mozilla/5.0 (MutantGen-{generation}-{self.rng.randint(100,999)})"
        elif mutation_type == "timing_jitter":
            genome["inter_arrival_ms"] = max(5.0, genome["inter_arrival_ms"] + self.rng.uniform(-15.0, 25.0))
        elif mutation_type == "payload_obfuscate":
            variants = [
                "UNI/**/ON SEL/**/ECT * FROM users",
                "' OR 1=1 --",
                '{"quantity": -25, "role": "admin"}',
                "${jndi:ldap://127.0.0.1/a}",
                "admin'/**/OR/**/'1'='1",
            ]
            genome["payload"] = self.rng.choice(variants)
        return genome

    def _evaluate_blue_gateway(self, genome: Dict) -> float:
        telemetry = self.correlator.extract_telemetry(
            peer_ip="192.168.1.99",
            peer_port=54321,
            headers={"x-forwarded-for": genome["xff"], "user-agent": genome["ua"]},
            override_metrics=(14.2, 0.4, 10, 1460, 0),
        )

        payload_str = genome["payload"]
        raw_malicious = 1.0 if any(k in payload_str.upper() for k in ["UNION", "SELECT", "OR 1=1", "ADMIN", "JNDI", "/**/"]) else 0.1
        if payload_str in self.learned_obfuscations:
            raw_malicious = 1.0

        spoof_signal = 1.0 if telemetry.spoof_detected else 0.0
        cadence_signal = 1.0 if genome["inter_arrival_ms"] < 40.0 else 0.35

        features = np.array([raw_malicious, spoof_signal, cadence_signal])
        raw_t_score = float(np.dot(self.blue_weights, features))
        return self.dp.perturb_threat_score(raw_t_score)

    def run_tournament(self, total_rounds: int = 500) -> TournamentMetrics:
        metrics = TournamentMetrics(rounds=total_rounds)
        best_genome = {
            "xff": "10.0.0.5",
            "ua": "Mozilla/5.0",
            "inter_arrival_ms": 12.0,
            "payload": "' OR 1=1 --",
        }
        best_red_score = 1.0
        window_evasions = 0

        for rnd in range(1, total_rounds + 1):
            candidate = self._mutate_red_attack(rnd, best_genome)
            t_score = self._evaluate_blue_gateway(candidate)

            if t_score < 0.50:
                metrics.evasions += 1
                window_evasions += 1
                if t_score < best_red_score:
                    best_red_score = t_score
                    best_genome = candidate

                self.learned_obfuscations.add(candidate["payload"])
                metrics.captured_signatures.append(candidate["payload"])
                self.blue_weights = np.clip(self.blue_weights + np.array([0.03, 0.04, 0.02]), 0.1, 0.85)
                self.blue_weights /= np.sum(self.blue_weights)
            elif t_score > 0.75:
                metrics.shadow_captures += 1
            else:
                metrics.blocked += 1

            if rnd % 50 == 0:
                metrics.evasion_curve.append(round(window_evasions / 50.0, 4))
                window_evasions = 0

        return metrics


if __name__ == "__main__":
    arena = RedBlueSelfPlayArena()
    res = arena.run_tournament(500)
    print(f"500-Round Self-Play Complete | Evasions: {res.evasions} | Shadow Captures: {res.shadow_captures} | Blocked: {res.blocked}")
    print(f"Evasion Rate Curve (per 50 rounds): {res.evasion_curve}")
