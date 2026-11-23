import asyncio
import hashlib
import json
import sqlite3
import time
import urllib.request
from typing import Any, Dict, List


class StatefulShadowHoneypot:
    def __init__(self, ollama_url: str = "http://localhost:11434/api/generate", model: str = "llama3.2:1b"):
        self.ollama_url = ollama_url
        self.model = model
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cur = self.db.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS canary_tokens (
                canary_id TEXT PRIMARY KEY,
                attacker_fp TEXT,
                endpoint TEXT,
                issued_at REAL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS captured_ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker_fp TEXT,
                step_num INTEGER,
                method TEXT,
                endpoint TEXT,
                payload TEXT,
                canary_issued TEXT,
                timestamp REAL
            )
            """
        )
        self.db.commit()

    def mint_canary_token(self, attacker_fp: str, endpoint: str) -> str:
        digest = hashlib.sha256(f"{attacker_fp}:{endpoint}:{time.time()}".encode()).hexdigest()[:16]
        canary = f"sk_live_canary_{digest}"
        cur = self.db.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO canary_tokens VALUES (?, ?, ?, ?)",
            (canary, attacker_fp, endpoint, time.time()),
        )
        self.db.commit()
        return canary

    def _generate_ollama_decoy_sync(self, endpoint: str, payload: Dict[str, Any], canary: str) -> Dict[str, Any]:
        prompt = (
            f"Generate a realistic, concise JSON API response for endpoint '{endpoint}' "
            f"that subtly includes the canary token '{canary}' inside a fake user or config object. "
            f"Return valid JSON only."
        )
        req_body = json.dumps({"model": self.model, "prompt": prompt, "stream": False, "format": "json"}).encode()
        req = urllib.request.Request(self.ollama_url, data=req_body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode())
                return json.loads(data.get("response", "{}"))
        except Exception:
            return {
                "status": "success",
                "environment": "prod-internal-east",
                "account": {
                    "id": "usr_9948102",
                    "role": "service_admin",
                    "internal_api_key": canary,
                    "db_replica": "10.240.18.92:5432",
                },
            }

    async def engage_shadow_session(
        self,
        attacker_fp: str,
        method: str,
        endpoint: str,
        payload: Dict[str, Any],
        tarpit_delay_ms: float = 15.0,
    ) -> Dict[str, Any]:
        cur = self.db.cursor()
        cur.execute("SELECT COUNT(*) FROM captured_ttps WHERE attacker_fp = ?", (attacker_fp,))
        step_num = cur.fetchone()[0] + 1

        delay_sec = min((tarpit_delay_ms * step_num) / 1000.0, 0.15)
        await asyncio.sleep(delay_sec)

        canary = self.mint_canary_token(attacker_fp, endpoint)
        loop = asyncio.get_running_loop()
        decoy_body = await loop.run_in_executor(
            None, self._generate_ollama_decoy_sync, endpoint, payload, canary
        )

        cur.execute(
            "INSERT INTO captured_ttps (attacker_fp, step_num, method, endpoint, payload, canary_issued, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (attacker_fp, step_num, method, endpoint, json.dumps(payload), canary, time.time()),
        )
        self.db.commit()

        return {
            "status_code": 200,
            "shadow_routed": True,
            "canary_token": canary,
            "step_captured": step_num,
            "body": decoy_body,
        }

    def get_attacker_chain(self, attacker_fp: str) -> List[Dict[str, Any]]:
        cur = self.db.cursor()
        cur.execute(
            "SELECT step_num, method, endpoint, payload, canary_issued FROM captured_ttps "
            "WHERE attacker_fp = ? ORDER BY step_num ASC",
            (attacker_fp,),
        )
        return [
            {
                "step": r[0],
                "method": r[1],
                "endpoint": r[2],
                "payload": json.loads(r[3]),
                "canary": r[4],
            }
            for r in cur.fetchall()
        ]
