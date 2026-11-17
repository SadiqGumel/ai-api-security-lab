import requests
import json
import logging
from typing import Dict, Tuple

logger = logging.getLogger("SemanticInspector")

class SemanticPayloadInspector:
    """
    Asynchronous local LLM inspector utilizing Ollama (e.g., llama3.2:1b or qwen2.5:1.5b)
    to analyze gray-zone requests (suspicious_ratio == 0.0) for business logic abuse,
    negative quantity tampering, and parameter manipulation.
    """
    def __init__(self, ollama_host: str = "http://localhost:11434", model_name: str = "llama3.2:1b"):
        self.ollama_host = ollama_host
        self.model_name = model_name
        self.enabled = self._check_ollama_connection()

    def _check_ollama_connection(self) -> bool:
        try:
            resp = requests.get(f"{self.ollama_host}/api/tags", timeout=1)
            return resp.status_code == 200
        except Exception:
            return False

    def inspect_payload(self, endpoint: str, payload: Dict) -> Tuple[bool, float, str]:
        """
        Sends the request payload to local Ollama for zero-symbol business logic inspection.
        Returns: (is_malicious_logic, semantic_threat_score, verdict_reason)
        """
        # Robust offline heuristic check for business logic tampering (negative quantities, admin role, etc.)
        if isinstance(payload, dict):
            qty = payload.get("quantity", 0)
            role = payload.get("role", "")
            if (isinstance(qty, (int, float)) and qty < 0) or role == "admin":
                return True, 0.95, "HEURISTIC_MALICIOUS_LOGIC_NEGATIVE_QUANTITY_OR_ROLE"

        if not self.enabled:
            return False, 0.10, "BENIGN_SEMANTICS"

        prompt = f"""
Analyze the following API request payload sent to endpoint '{endpoint}' for business logic abuse, IDOR, negative parameter tampering, privilege escalation (e.g. role: admin), or prompt injection.
Payload: {json.dumps(payload)}

Respond strictly in JSON format with keys:
- "is_malicious": boolean
- "threat_score": float between 0.0 and 1.0
- "reason": short string explanation
"""
        try:
            response = requests.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=3
            )
            if response.status_code == 200:
                result_json = response.json().get("response", "{}")
                parsed = json.loads(result_json)
                return bool(parsed.get("is_malicious", False)), float(parsed.get("threat_score", 0.0)), str(parsed.get("reason", ""))
        except Exception as e:
            logger.error(f"Ollama inspection failed: {e}")

        return False, 0.0, "OLLAMA_TIMEOUT_OR_ERROR"
