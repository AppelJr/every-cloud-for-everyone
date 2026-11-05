# MCP authority boundary — integration status

`dispatcher.py` is a fail-closed execution adapter, not an MCP server or a claim of production deployment. It executes no tools by default. The `echo` policy in tests is test-only; deployments must inject a reviewed, fixed-path allowlist and an audit ledger location.

## Required host integration before production

1. The MCP host authenticates the transport/session and passes an `Identity` derived from that trusted context. Never construct identity or capabilities from model-supplied `tools/call` JSON.
2. The host maps authenticated grants to narrowly scoped capabilities (for example, `tool:read_document`) and supplies only a fixed-path tool policy. Never accept executable paths from requests.
3. Configure the ledger in a protected local directory, monitor/backup it, and test startup, corruption, full-disk, permissions, and recovery behavior. The SHA3-512 chain detects edits but is not tamper-proof against truncation without an external anchor.
4. Run the denial matrix and platform-specific subprocess/audit tests on the actual air-gapped target. No production promotion until those checks and an independent security review pass.

Every request is denied when identity, capability, allowlist, or audit admission is absent. The standalone stdin entry point intentionally cannot execute anything because it has no trusted authentication context. Audit records omit arguments, credentials, and output. An authorized intent is recorded and fsynced before execution; completion is recorded before output is returned.
