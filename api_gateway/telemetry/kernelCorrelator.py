import hashlib
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
import numpy as np


@dataclass
class SocketTelemetry:
    peer_ip: str
    peer_port: int
    rtt_ms: float
    rtt_var_ms: float
    cwnd: int
    mss: int
    retransmits: int
    stack_fingerprint: str
    spoof_detected: bool


class KernelSocketCorrelator:
    def __init__(self):
        self._fingerprint_history: Dict[str, set] = {}
        self._rtt_history: Dict[str, list] = {}

    def _query_ss_socket(self, peer_ip: str, peer_port: int) -> Tuple[float, float, int, int, int]:
        try:
            cmd = ["ss", "-tin", "dst", f"{peer_ip}:{peer_port}"]
            out = subprocess.check_output(cmd, text=True, timeout=0.15)
            rtt_match = re.search(r"rtt:([\d.]+)/([\d.]+)", out)
            cwnd_match = re.search(r"cwnd:(\d+)", out)
            mss_match = re.search(r"mss:(\d+)", out)
            retrans_match = re.search(r"retrans:\d+/(\d+)", out)

            rtt = float(rtt_match.group(1)) if rtt_match else 1.5
            rtt_var = float(rtt_match.group(2)) if rtt_match else 0.2
            cwnd = int(cwnd_match.group(1)) if cwnd_match else 10
            mss = int(mss_match.group(1)) if mss_match else 1460
            retrans = int(retrans_match.group(1)) if retrans_match else 0
            return rtt, rtt_var, cwnd, mss, retrans
        except Exception:
            return 1.2, 0.15, 10, 65495 if peer_ip.startswith("127.") else 1460, 0

    def extract_telemetry(
        self,
        peer_ip: str,
        peer_port: int,
        headers: Dict[str, str],
        override_metrics: Optional[Tuple[float, float, int, int, int]] = None,
    ) -> SocketTelemetry:
        rtt, rtt_var, cwnd, mss, retrans = (
            override_metrics if override_metrics else self._query_ss_socket(peer_ip, peer_port)
        )

        rtt_bucket = round(rtt / 2.0) * 2
        stack_raw = f"{mss}:{cwnd}:{rtt_bucket}:{peer_ip.rsplit('.', 1)[0]}"
        stack_fp = hashlib.sha256(stack_raw.encode()).hexdigest()[:16]

        claimed_id = f"{headers.get('x-forwarded-for', peer_ip)}|{headers.get('user-agent', 'unknown')}"
        seen_identities = self._fingerprint_history.setdefault(stack_fp, set())
        seen_identities.add(claimed_id)
        spoof_detected = len(seen_identities) > 3

        rtts = self._rtt_history.setdefault(stack_fp, [])
        rtts.append(rtt)
        if len(rtts) > 50:
            rtts.pop(0)
        empirical_var = float(np.var(rtts)) if len(rtts) > 1 else rtt_var

        return SocketTelemetry(
            peer_ip=peer_ip,
            peer_port=peer_port,
            rtt_ms=rtt,
            rtt_var_ms=empirical_var,
            cwnd=cwnd,
            mss=mss,
            retransmits=retrans,
            stack_fingerprint=stack_fp,
            spoof_detected=spoof_detected,
        )

    def to_feature_vector(self, telemetry: SocketTelemetry) -> np.ndarray:
        return np.array(
            [
                telemetry.rtt_ms,
                telemetry.rtt_var_ms,
                float(telemetry.cwnd),
                float(telemetry.retransmits) + (5.0 if telemetry.spoof_detected else 0.0),
            ],
            dtype=np.float64,
        )
