"""Python client for the Rust sovereign-sealer CLI. No Python crypto reimplementation."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any

class SealerError(RuntimeError):
    pass

class Sealer:
    def __init__(self, executable: str | Path = "sovereign-sealer", timeout: float = 30.0):
        self.executable = str(executable)
        self.timeout = timeout

    def _call(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            proc = subprocess.run([self.executable], input=json.dumps(request), text=True,
                                  capture_output=True, timeout=self.timeout, check=False,
                                  shell=False, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SealerError("native_sealer_unavailable_or_timeout") from exc
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise SealerError("native_sealer_invalid_response") from exc
        if proc.returncode != 0 or result.get("status") != "success":
            raise SealerError(result.get("error", "native_sealer_failed"))
        return result

    def seal(self, plaintext: bytes, password: str, associated_data: bytes = b"") -> dict[str, Any]:
        import base64
        return self._call({"operation":"seal","password":password,"provider":"Local",
            "plaintext_b64":base64.b64encode(plaintext).decode(),
            "associated_data_b64":base64.b64encode(associated_data).decode()})

    def open(self, blob: bytes, record: dict[str, Any], password: str,
             associated_data: bytes = b"") -> bytes:
        import base64
        result = self._call({"operation":"open","password":password,"provider":"Local",
            "blob_b64":base64.b64encode(blob).decode(),"record":record,
            "associated_data_b64":base64.b64encode(associated_data).decode()})
        return base64.b64decode(result["plaintext_b64"], validate=True)
