# Portable Sealer — initial native-core package

This directory introduces a Rust-owned cryptographic core and Python/Node.js process clients. It is an implementation foundation, **not yet a certified or production-ready universal SDK**.

## Current design

- Rust crate + CLI: Argon2id v1.3 (64 MiB, 3 iterations, 1 lane) derives a 256-bit key; AES-256-GCM encrypts/authenticates.
- Python and Node.js call the same native CLI. They do not independently implement cryptography.
- Wire payloads are JSON; binary data is base64; associated data is authenticated.
- Only the `Local` provider is accepted. No provider network integration is present.

## Build

From this directory:

```sh
cargo test --manifest-path rust/Cargo.toml
cargo build --release --manifest-path rust/Cargo.toml
```

Set `SOVEREIGN_SEALER_BIN` to the resulting executable when running language clients:

```sh
SOVEREIGN_SEALER_BIN=rust/target/release/sovereign-sealer python3 -m unittest discover -s python -v
SOVEREIGN_SEALER_BIN=rust/target/release/sovereign-sealer node --test javascript/test/*.test.mjs
```

## Platform status

| Platform | Status |
|---|---|
| Linux / Windows / macOS | Rust CLI can be built per target; CI and packaging still required |
| Python | Process client added; requires Rust CLI installed |
| Node.js | Process client added; requires Rust CLI installed |
| iOS | Existing Swift package remains separate; cross-language vector compatibility not yet proven |
| Android | No JNI/NDK or Kotlin binding yet; not supported by this commit |
| Browser | Not supported; Node client is not browser compatible |

## Security limitations — do not skip

- The Rust CLI currently accepts a password in JSON stdin. Production deployments should use an authenticated key-provider interface or protected IPC, avoid password logging, and minimize process-memory lifetime.
- The record timestamp is currently a placeholder, not trusted time.
- Salt/nonce randomness uses the OS CSPRNG. Password KDF parameters are versioned in the record.
- The CLI's JSON interface and process clients need request-size, memory, and lifecycle hardening before untrusted multi-tenant use.
- No hardware-backed key storage, OS sandbox, secure enclave, Android Keystore, TPM, or attestation integration is included.
- The existing Swift V1.1 implementation is not yet proven byte-compatible with this Rust format.
- Passing unit tests do not constitute cryptographic review or production certification.

## Acceptance gate

Do not mark universal compatibility until the same published deterministic test vectors are verified independently across Rust, Python, Node, Swift, and Android. Do not claim Android/iOS support until native platform bindings and device CI pass.
