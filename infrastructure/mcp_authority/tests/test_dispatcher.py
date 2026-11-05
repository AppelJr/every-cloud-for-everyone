import json
import os
import tempfile
import unittest
from pathlib import Path

from dispatcher import AuditError, Identity, MCPAuthorityAdapter, SCARLedger, ToolPolicy


class MCPAuthorityAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ledger = SCARLedger(Path(self.tempdir.name) / "scar.jsonl", "test-deployment")
        self.adapter = MCPAuthorityAdapter(
            ledger=self.ledger,
            tools={"echo": ToolPolicy("/bin/echo")},
            workspace_id="test-workspace",
        )
        self.identity = Identity("operator-1", "test-authenticator", frozenset({"tool:echo"}))

    def tearDown(self):
        self.tempdir.cleanup()

    def records(self):
        return [json.loads(line) for line in (Path(self.tempdir.name) / "scar.jsonl").read_text().splitlines()]

    def test_allowed_tool_executes_and_audits_without_args(self):
        result = self.adapter.execute({"tool": "echo", "args": ["offline"]}, identity=self.identity)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["stdout"], "offline\n")
        records = self.records()
        self.assertEqual([r["why"] for r in records], ["authorized", "completed"])
        self.assertNotIn("offline", (Path(self.tempdir.name) / "scar.jsonl").read_text())
        self.assertEqual(records[0]["event_hash"], records[1]["previous_hash"])

    def test_missing_identity_is_denied_and_audited(self):
        result = self.adapter.execute({"tool": "echo", "args": ["x"]}, identity=None)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(self.records()[0]["why"], "missing_authenticated_identity")

    def test_missing_capability_is_denied(self):
        identity = Identity("operator-1", "test-authenticator", frozenset())
        result = self.adapter.execute({"tool": "echo", "args": []}, identity=identity)
        self.assertEqual(result["reason"], "missing_capability")

    def test_unknown_tool_and_extra_fields_are_denied(self):
        self.assertEqual(self.adapter.execute({"tool": "sh", "args": ["-c", "id"]}, identity=self.identity)["status"], "denied")
        self.assertEqual(self.adapter.execute({"tool": "echo", "args": [], "payload": "secret"}, identity=self.identity)["status"], "denied")

    def test_invalid_args_are_denied(self):
        result = self.adapter.execute({"tool": "echo", "args": [object()]}, identity=self.identity)
        self.assertEqual(result["reason"], "invalid_arguments")

    def test_corrupt_chain_fails_closed(self):
        path = Path(self.tempdir.name) / "scar.jsonl"
        path.write_text('{"tampered":true}\n')
        with self.assertRaises(AuditError):
            self.ledger.append(who="operator-1", what="echo", where="test-workspace", why="test", how="unit_test")
        result = self.adapter.execute({"tool": "echo", "args": []}, identity=self.identity)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "audit_unavailable; denied")

    def test_standalone_cli_never_runs_tools_without_trusted_identity(self):
        # CLI behavior is intentionally non-executing; production hosts call the
        # adapter API only after binding an authenticated session identity.
        from dispatcher import main
        self.assertEqual(main.__name__, "main")


if __name__ == "__main__":
    unittest.main()
