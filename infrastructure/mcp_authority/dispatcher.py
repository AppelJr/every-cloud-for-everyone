#!/usr/bin/env python3
"""Fail-closed local tool dispatcher for an authenticated MCP host.

This module is an adapter, not an MCP server. The MCP host MUST pass an
identity established by trusted transport/session authentication; never build
Identity from the model's JSON request. Tools are fixed executable paths and
there is no shell. No tool is enabled unless explicitly configured.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

MAX_OUTPUT_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 16 * 1024
MAX_ARGS = 8
MAX_ARG_BYTES = 1024
MAX_AUDIT_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class Identity:
    """Authenticated context supplied by the MCP host, not request JSON."""

    subject: str
    authn_method: str
    capabilities: frozenset[str]


@dataclass(frozen=True)
class ToolPolicy:
    executable: str
    max_args: int = MAX_ARGS
    max_arg_bytes: int = MAX_ARG_BYTES
    timeout_seconds: int = TIMEOUT_SECONDS


@dataclass(frozen=True)
class AuditDecision:
    timestamp: str
    deployment: str
    who: str
    what: str
    where: str
    why: str
    how: str
    previous_hash: str
    event_hash: str


class AuditError(RuntimeError):
    pass


class SCARLedger:
    """Local SHA3-512 chained audit log; corruption or write failure is fatal.

    Protect the parent directory and preserve/replicate this ledger using the
    deployment's trusted storage policy. A hash chain detects edits, but does
    not by itself prevent an administrator from truncating the file.
    """

    _GENESIS = "0" * 128

    def __init__(self, path: str | os.PathLike[str], deployment: str) -> None:
        self.path = Path(path)
        self.deployment = deployment
        self._thread_lock = threading.Lock()
        if not deployment or len(deployment) > 128:
            raise ValueError("Invalid deployment identifier")

    @staticmethod
    def _canonical(value: Mapping[str, Any]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def _read_and_verify(self, fd: int) -> str:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AUDIT_BYTES:
                raise AuditError("SCAR ledger exceeds configured size limit")
            chunks.append(chunk)
        data = b"".join(chunks)
        previous = self._GENESIS
        if data and not data.endswith(b"\n"):
            raise AuditError("SCAR ledger has an incomplete final record")
        for line in data.splitlines():
            try:
                record = json.loads(line)
                supplied_hash = record.pop("event_hash")
                if record.get("previous_hash") != previous:
                    raise AuditError("SCAR chain link mismatch")
                expected = hashlib.sha3_512(self._canonical(record)).hexdigest()
                if not isinstance(supplied_hash, str) or not __import__("hmac").compare_digest(supplied_hash, expected):
                    raise AuditError("SCAR record hash mismatch")
                previous = supplied_hash
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                if isinstance(exc, AuditError):
                    raise
                raise AuditError("SCAR ledger is malformed") from exc
        return previous

    def append(self, *, who: str, what: str, where: str, why: str, how: str) -> AuditDecision:
        # Audit metadata is deliberately bounded and excludes args, credentials,
        # tool output, and raw request payloads.
        fields = {"who": who, "what": what, "where": where, "why": why, "how": how}
        if any(not isinstance(value, str) or not value or len(value) > 256 for value in fields.values()):
            raise AuditError("Invalid SCAR metadata")
        timestamp = datetime.now(timezone.utc).isoformat()
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._thread_lock:
            try:
                fd = os.open(self.path, flags, stat.S_IRUSR | stat.S_IWUSR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_AUDIT_BYTES:
                        raise AuditError("SCAR ledger is not a safe regular file or is too large")
                    previous = self._read_and_verify(fd)
                    body = {
                        "timestamp": timestamp,
                        "deployment": self.deployment,
                        **fields,
                        "previous_hash": previous,
                    }
                    event_hash = hashlib.sha3_512(self._canonical(body)).hexdigest()
                    line = self._canonical({**body, "event_hash": event_hash}) + b"\n"
                    if info.st_size + len(line) > MAX_AUDIT_BYTES:
                        raise AuditError("SCAR ledger size limit reached")
                    view = memoryview(line)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    os.close(fd)
            except OSError as exc:
                raise AuditError("SCAR ledger unavailable") from exc
        return AuditDecision(timestamp, self.deployment, who, what, where, why, how, previous, event_hash)


class MCPAuthorityAdapter:
    """Authorize, audit, then invoke a configured local executable."""

    def __init__(
        self,
        *,
        ledger: SCARLedger,
        tools: Mapping[str, ToolPolicy] | None = None,
        workspace_id: str,
    ) -> None:
        self.ledger = ledger
        self.tools = dict(tools or {})  # Empty by default: deny all.
        self.workspace_id = workspace_id
        if not workspace_id or len(workspace_id) > 128:
            raise ValueError("Invalid workspace identifier")
        for name, policy in self.tools.items():
            if (not name or len(name) > 64 or not os.path.isabs(policy.executable)
                    or policy.max_args < 0 or policy.max_args > MAX_ARGS
                    or policy.max_arg_bytes < 1 or policy.max_arg_bytes > MAX_ARG_BYTES
                    or not 1 <= policy.timeout_seconds <= TIMEOUT_SECONDS):
                raise ValueError("Invalid tool policy")

    def execute(self, request: Any, *, identity: Identity | None) -> dict[str, Any]:
        """Execute one request. Identity MUST come from trusted host middleware."""
        tool = request.get("tool") if isinstance(request, dict) else None
        display_tool = tool if isinstance(tool, str) and len(tool) <= 64 else "invalid"
        if identity is None or not identity.subject or not identity.authn_method:
            return self._deny(display_tool, "missing_authenticated_identity", "unknown", "none")

        policy = self.tools.get(tool) if isinstance(tool, str) else None
        if policy is None:
            return self._deny(display_tool, "tool_not_allowlisted", identity.subject, identity.authn_method)
        if not isinstance(request, dict) or set(request) - {"tool", "args"}:
            return self._deny(display_tool, "invalid_request_shape", identity.subject, identity.authn_method)
        args = request.get("args", [])
        if (not isinstance(args, list) or len(args) > policy.max_args
                or any(not isinstance(arg, str) or len(arg.encode("utf-8")) > policy.max_arg_bytes for arg in args)):
            return self._deny(display_tool, "invalid_arguments", identity.subject, identity.authn_method)
        if not isinstance(identity.capabilities, frozenset) or f"tool:{tool}" not in identity.capabilities:
            return self._deny(display_tool, "missing_capability", identity.subject, identity.authn_method)
        try:
            encoded_request = self._canonical_request(request)
            if len(encoded_request) > MAX_REQUEST_BYTES:
                return self._deny(display_tool, "request_too_large", identity.subject, identity.authn_method)
        except (TypeError, ValueError):
            return self._deny(display_tool, "invalid_request", identity.subject, identity.authn_method)

        try:
            self.ledger.append(who=identity.subject, what=display_tool, where=self.workspace_id,
                               why="authorized", how=identity.authn_method + "; capability:tool:" + tool)
        except AuditError:
            return {"status": "error", "reason": "audit_unavailable; execution_not_started"}

        try:
            result = subprocess.run(
                [policy.executable, *args], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=policy.timeout_seconds, check=False, shell=False,
                close_fds=True, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            stdout = result.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            stderr = result.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            status = "success" if result.returncode == 0 else "error"
            reason = "completed" if status == "success" else "tool_nonzero_exit"
            returncode: int | None = result.returncode
        except subprocess.TimeoutExpired:
            status, reason, returncode, stdout, stderr = "error", "tool_timeout", None, "", ""
        except OSError:
            status, reason, returncode, stdout, stderr = "error", "tool_launch_failed", None, "", ""

        try:
            self.ledger.append(who=identity.subject, what=display_tool, where=self.workspace_id,
                               why=reason, how="execution_result")
        except AuditError:
            # Withhold output if the completion record cannot be committed.
            return {"status": "error", "reason": "audit_completion_failed; output_withheld"}
        return {"status": status, "returncode": returncode, "stdout": stdout, "stderr": stderr}

    @staticmethod
    def _canonical_request(request: dict[str, Any]) -> bytes:
        return json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _deny(self, tool: str, reason: str, who: str, how: str) -> dict[str, Any]:
        try:
            self.ledger.append(who=who[:256] or "unknown", what=tool, where=self.workspace_id,
                               why=reason, how=how[:256] or "none")
        except AuditError:
            return {"status": "error", "reason": "audit_unavailable; denied"}
        return {"status": "denied", "reason": reason}


def main() -> int:
    """Standalone stdin mode cannot authenticate MCP sessions and always denies."""
    try:
        raw = __import__("sys").stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            response = {"status": "denied", "reason": "request_too_large"}
        else:
            json.loads(raw)
            response = {"status": "denied", "reason": "trusted_mcp_identity_required"}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        response = {"status": "error", "reason": "invalid_json"}
    print(json.dumps(response, separators=(",", ":")))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
