# Universal Cloud Sealer v1.1 — canonical integration

## SealRecord

Canonical JSON is UTF-8, lexicographically sorted keys, with no insignificant whitespace:

```json
{"algorithm":"AES-256-GCM","blob_sha256":"","key_id":"","nonce":"","provider":"","salt":"","sealed_at":"","version":1}
```

The record persists an exact 16-byte base64 salt and exact 12-byte base64 nonce. `blob_sha256` is lowercase SHA-256 of the complete AES-GCM blob, including the appended 16-byte authentication tag.

## Provider policy

Blocked: Google, Meta, Mistral, Cohere, Perplexity, Together, Fireworks, Groq, AWS, Azure, Vercel.

Allowed: xAI, Local, OpenAI, Anthropic, Custom, iCloud, Dropbox, Box, OneDrive, pCloud, Mega, Proton, Sync.com, Wasabi, Backblaze, Storj, Cloudflare R2, Oracle, IBM, Alibaba, Tencent.

Unknown providers fail closed.

## Cryptography

Argon2id: 64 MiB memory, three passes, four lanes, 32-byte output. AES-256-GCM uses a 12-byte nonce and stores ciphertext plus tag as the blob. Verification checks the blob SHA-256 before decryption.

If Argon2id is unavailable at compile time, the compatibility path derives SHA3-512(password || salt), truncates to 32 bytes, and emits a durable `KDF_FALLBACK` SCAR event. This fallback is not equivalent security.

BLAKE3 has no role in SealRecord or AES-GCM seal/verify. It remains outside this primitive in the wider Sovereignty receipt/Merkle namespace.

## QResist

An integrity/authentication failure emits `INTEGRITY_FAILURE`, requests network isolation through an injected boundary, and terminates the current operation. The sealer does not directly control the OS network stack or infer provider malice.

SCAR fields: `sequence`, `event_type`, `timestamp`, `provider`, `reason`, `action`, `previous_event_hash`, `event_hash`. The event hash is SHA-256 of canonical JSON over all fields except `event_hash`.

## LockdownMode

Lockdown is capability enforcement, not environment mutation. External upload, external sync, external API use, and key export are denied; local vault and audit remain allowed.

## Cross-port invariant

Any conforming port can seal, and any other conforming port can verify with the same password, blob, and complete SealRecord. The persisted salt is the structural requirement that makes this invariant possible.
