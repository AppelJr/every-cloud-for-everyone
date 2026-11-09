[![Swift](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/swift.yml/badge.svg)](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/swift.yml)
[![Offline dispatcher](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/offline-dispatcher.yml/badge.svg)](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/offline-dispatcher.yml) [![Portable sealer core](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/portable-sealer.yml/badge.svg)](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/portable-sealer.yml)

# every-cloud-for-everyone

> **When companies write a privacy policy and don't follow it, we enforce their own policy — keeping every customer safe with their own key.**

## Project status

This repository is a work in progress. The Swift package and Python offline-dispatcher adapter are separate components. This repository does **not** yet provide a shared Rust core or production-ready Rust, Python, and JavaScript cryptographic packages. The current cloud-provider names are an intended integration scope, not proof that provider adapters exist or have been verified.

The current `UniversalCloudSealer` prototype records provider/mode metadata; it is not a verified file-encryption implementation. Do not use it to protect production data. The V1.1 password-based test/API mismatch must be resolved before the Swift package can be considered complete.

## Offline local tool dispatcher

`infrastructure/mcp_authority/dispatcher.py` provides a fail-closed adapter for an authenticated host to invoke a narrowly allowlisted local executable without a shell.

The host—not the model request—must supply the authenticated `Identity` and its capabilities. The standalone stdin entry point deliberately refuses execution because JSON input alone cannot establish trusted identity or authorization.

Deployment requirements:

- Never construct identity or capabilities from model-supplied JSON.
- Configure absolute executable paths and narrowly scoped tool policies in trusted host code.
- Do not allowlist a shell, general-purpose interpreter, package manager, or other unrestricted command as a model-callable production tool.
- Keep the audit ledger and its parent directory under trusted operating-system permissions.
- The SHA3-512 hash chain detects record edits, but does not prevent privileged truncation or replacement.
- Apply OS-level isolation and independently review deployment policy. This adapter is not a complete MCP server, authentication system, sandbox, or production certification.
- The current ledger implementation uses POSIX `fcntl`; Windows support is not claimed.
- This dispatcher invokes configured local tools only; it does not implement cloud-provider adapters.

## Run repository checks

Requirements: Swift 5.9+ and Python 3.11+. On supported macOS or Linux environments, run from the repository root:

```bash
./scripts/test-all.sh
```

The script runs both `swift test` and the Python dispatcher unittest suite, even if one fails, then returns non-zero if either suite fails. A successful Python suite does not imply that the Swift suite or the full project is production-ready.

Run only the offline dispatcher tests:

```bash
cd infrastructure/mcp_authority
python3 -m unittest discover -s tests -v
```

The offline-dispatcher CI matrix runs on Ubuntu and macOS with Python 3.11 and 3.12. The Swift workflow remains separate. Windows, Android, browser, Rust, and JavaScript support are not currently claimed or tested.

A green check proves only that the tests in that workflow passed. It is not a security certification, cryptographic interoperability proof, or production-readiness attestation.

## Swift package

The Swift package is currently a prototype. Before production use, the project needs a real, reviewed encryption implementation, independent fixed test vectors, and verified cross-language interoperability. Do not infer encryption from metadata, hashes, or successful unit tests alone.

Run the Swift package tests with:

```bash
swift test
```

## License

MIT — see [LICENSE](LICENSE).
