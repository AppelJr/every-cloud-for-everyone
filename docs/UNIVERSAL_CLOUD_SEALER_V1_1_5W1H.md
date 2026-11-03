# Universal Cloud Sealer v1.1 — 5W1H implementation receipt

## WHO
Company implementation work is isolated to branch `codex/universal-cloud-sealer-v1.1` in `AppelJr/every-cloud-for-everyone`. The repository owner retains final base-branch authority.

## WHAT
Port the canonical Universal Cloud Sealer v1.1 contract into the Swift package: persisted 16-byte salt, 12-byte nonce, AES-256-GCM, SHA-256 blob digest, Argon2id KDF, fail-closed provider policy, SCAR-compatible integrity events, injected network-boundary isolation, and capability-based LockdownMode.

## WHEN
The implementation branch was created from the repository `main` head before implementation. Native Swift execution is not claimed from this environment.

## WHERE
Swift implementation paths:
- `Sources/EveryCloudForEveryone/Models/SealRecord.swift`
- `Sources/EveryCloudForEveryone/Core/ProviderPolicyV1_1.swift`
- `Sources/EveryCloudForEveryone/Core/NetworkBoundary.swift`
- `Sources/EveryCloudForEveryone/Core/SCARLedgerV1_1.swift`
- `Sources/EveryCloudForEveryone/Core/UniversalCloudSealerV1_1.swift`
- `Sources/EveryCloudForEveryone/Crypto/Argon2KDFV1_1.swift`
- `Tests/EveryCloudForEveryoneTests/UniversalCloudSealerV1_1Tests.swift`

## WHY
The v1.0 contract omitted the KDF salt from `SealRecord`, making cross-port verification impossible by construction. v1.1 persists the salt and freezes the cryptographic and control-plane semantics so another conforming port can verify the same blob.

## HOW
1. Generate a fresh salt and nonce for each seal.
2. Derive the 32-byte key with Argon2id (64 MiB, three passes, four lanes).
3. Encrypt with AES-256-GCM; persist ciphertext plus tag as the blob.
4. Hash the complete blob with SHA-256.
5. Persist the complete eight-field `SealRecord` using sorted-key canonical JSON.
6. Verify the digest before decrypting.
7. On authentication/integrity failure, emit `INTEGRITY_FAILURE`, request `denyAll()` through the injected network boundary, and throw/terminate the current operation.
8. Lockdown denies external capabilities while preserving local vault and audit capabilities.

## EVIDENCE STATUS
- Branch creation: PASS — branch exists.
- Repository/base authority: PASS — target is `AppelJr/every-cloud-for-everyone`, base is `main`.
- Salt persisted in contract: PASS — implemented and tested in source.
- Cross-port deterministic vector: PASS — exact v1.1 reference values embedded in Swift test.
- Native Swift build/test: NOT RUN — dependency/toolchain execution was unavailable in the current execution environment.
- Base branch mutation: NOT RUN — no merge or base update performed.

## FINAL AUTHORITY
This branch is a company implementation contribution only. Final review, acceptance, and push/merge to `main` remain with the repository owner.
