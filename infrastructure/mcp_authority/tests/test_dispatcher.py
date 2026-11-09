import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dispatcher import AuditError, Identity, MCPAuthorityAdapter, SCARLedger, ToolPolicy


class MCPAuthorityAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.tempdir.name) / "scar.jsonl"
        self.ledger = SCARLedger(self.ledger_path, "test-deployment")
        # Test-only executable policy. The interpreter is fixed by the test
        # harness and is never exposed as a production model-callable tool.
        self.adapter = MCPAuthorityAdapter(
            ledger=self.ledger,
            tools={"test_helper": ToolPolicy(sys.executable, timeout_seconds=2)},
            workspace_id="test-workspace",
        )
        self.identity = Identity(
            "operator-1", "test-authenticator", frozenset({"tool:test_helper"})
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def records(self):
        return [
            json.loads(line)
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines()
        ]

    def call_helper(self, code, *, timeout=2):
        adapter = MCPAuthorityAdapter(
            ledger=self.ledger,
            tools={"test_helper": ToolPolicy(sys.executable, timeout_seconds=timeout)},
            workspace_id="test-workspace",
        )
        return adapter.execute(
            {"tool": "test_helper", "args": ["-c", code]},
            identity=self.identity,
        )

    def test_allowed_tool_runs_and_audits_without_recording_arguments(self):
        result = self.call_helper("print('offline execution verified')")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["stdout"], "offline execution verified\n")
        records = self.records()
        self.assertEqual([record["why"] for record in records], ["authorized", "completed"])
        ledger_text = self.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn("offline execution verified", ledger_text)
        self.assertNotIn("-c", ledger_text)
        self.assertEqual(records[0]["event_hash"], records[1]["previous_hash"])

    def test_nonzero_exit_is_reported_and_audited(self):
        result = self.call_helper(
            "import sys; print('expected error', file=sys.stderr); sys.exit(7)"
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(result["stderr"], "expected error\n")
        self.assertEqual(self.records()[-1]["why"], "tool_nonzero_exit")

    def test_timeout_is_reported_and_audited(self):
        result = self.call_helper("import time; time.sleep(3)", timeout=1)
        self.assertEqual(result["reason"], "tool_timeout")
        self.assertEqual(self.records()[-1]["why"], "tool_timeout")

    def test_returned_output_is_truncated_to_response_limit(self):
        result = self.call_helper("print('x' * 70000)")
        self.assertEqual(result["status"], "success")
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), 64 * 1024)

    def test_missing_identity_is_denied_and_audited(self):
        result = self.adapter.execute(
            {"tool": "test_helper", "args": ["-c", "print('must not run')"]},
            identity=None,
        )
        self.assertEqual(result["status"], "denied")
        self.assertEqual(self.records()[0]["why"], "missing_authenticated_identity")

    def test_missing_capability_is_denied_and_audited(self):
        identity = Identity("operator-1", "test-authenticator", frozenset())
        result = self.adapter.execute(
            {"tool": "test_helper", "args": []}, identity=identity
        )
        self.assertEqual(result["reason"], "missing_capability")
        self.assertEqual(self.records()[-1]["why"], "missing_capability")

    def test_unknown_tool_and_extra_fields_are_denied(self):
        unknown = self.adapter.execute(
            {"tool": "sh", "args": ["-c", "id"]}, identity=self.identity
        )
        extra = self.adapter.execute(
            {"tool": "test_helper", "args": [], "payload": "secret"},
            identity=self.identity,
        )
        self.assertEqual(unknown["status"], "denied")
        self.assertEqual(extra["status"], "denied")

    def test_invalid_args_and_oversized_request_are_denied(self):
        invalid = self.adapter.execute(
            {"tool": "test_helper", "args": [object()]}, identity=self.identity
        )
        oversized = self.adapter.execute(
            {"tool": "test_helper", "args": ["x" * (16 * 1024)]},
            identity=self.identity,
        )
        self.assertEqual(invalid["reason"], "invalid_arguments")
        self.assertEqual(oversized["reason"], "invalid_arguments")

    def test_corrupt_audit_chain_fails_closed(self):
        self.ledger_path.write_text('{"tampered":true}\n', encoding="utf-8")
        with self.assertRaises(AuditError):
            self.ledger.append(
                who="operator-1",
                what="test_helper",
                where="test-workspace",
                why="test",
                how="unit_test",
            )
        result = self.adapter.execute(
            {"tool": "test_helper", "args": []}, identity=self.identity
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "audit_unavailable; execution_not_started")

    def test_stdin_cli_refuses_execution_without_host_identity(self):
        result = subprocess.run(
            [sys.executable, "dispatcher.py"],
            input='{"tool":"test_helper","args":[]}',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(result.stdout),
            {"status": "denied", "reason": "trusted_mcp_identity_required"},
        )


if __name__ == "__main__":
    unittest.main()
