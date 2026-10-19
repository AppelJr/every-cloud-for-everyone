[![Swift](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/swift.yml/badge.svg)](https://github.com/AppelJr/every-cloud-for-everyone/actions/workflows/swift.yml)
# every-cloud-for-everyone

> **When companies write a privacy policy and don't follow it, we enforce their own policy — keeping every customer safe with their own key.**

A Swift package that applies client-side encryption on top of every major cloud provider so the provider's own end-to-end encryption promise is kept, regardless of what their servers actually do.

---

## How it works

Every cloud account is *sealed* before any data leaves your device:

1. A passphrase is used to derive a 256-bit key with **Scrypt** (a memory-hard KDF similar in purpose to Argon2id, provided by CryptoSwift).
2. The plaintext is encrypted with AES-GCM — the cloud provider only ever receives ciphertext.
3. A SHA-256 integrity digest (Blake3-compatible interface) is computed and stored locally.
4. QResist monitors uplinks; if a digest mismatch is detected the uplink is killed.
5. LockdownMode can be activated to block all non-essential network traffic.

```
User passphrase
      │
      ▼
  Scrypt (memory-hard) ──► 256-bit key
      │
      ▼
  AES-GCM seal ──► ciphertext uploaded to cloud
      │
      ▼
  Blake3Hasher ──► integrity digest stored on-device
      │
      ▼
  QResist validates digest on every sync
```

---

## Supported cloud providers

| Category | Providers |
|---|---|
| Consumer | iCloud · Google Drive · OneDrive · Dropbox · MEGA · pCloud · Sync.com |
| Enterprise | AWS S3 · Azure Blob · Google Cloud Storage · Backblaze B2 · Wasabi · Cloudflare R2 · DigitalOcean Spaces |
| Self-hosted / privacy-first | Nextcloud · Box · SpiderOak · Tresorit · Proton Drive · Filen |
| Other infrastructure | Oracle Cloud · IBM Cloud · Alibaba Cloud · Tencent Cloud |

---

## Project structure

```
Package.swift
Sources/
  EveryCloudForEveryone/
    Models/
      CloudProvider.swift
      EncryptionMode.swift
    Core/
      ContractEnforcer.swift
      UniversalCloudSealer.swift
      QResist.swift
      LockdownMode.swift
      KeyManager.swift
    Crypto/
      Blake3Hasher.swift
      Argon2Wrapper.swift
Tests/
  EveryCloudForEveryoneTests/
```

---

## Getting started

### Requirements

- Swift 5.9+
- Linux (Ubuntu 22.04+) or macOS 13+

### Add as a Swift package

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/AppelJr/every-cloud-for-everyone.git", branch: "main")
],
targets: [
    .target(dependencies: [
        .product(name: "EveryCloudForEveryone", package: "every-cloud-for-everyone")
    ])
]
```

### Quick example

```swift
import EveryCloudForEveryone

let results = UniversalCloudSealer.shared.sealAll(passphrase: "user-passphrase")

let claim = ContractEnforcer.PolicyClaim(
    provider: "iCloud",
    claim: "End-to-end encryption so only you and the recipient can read your data.",
    promisesE2E: true,
    promisesUserKeys: false
)
let outcome = ContractEnforcer.shared.enforce(claim: claim)

QResist.shared.arm()
let onDevice = Blake3Hasher.hash(myFileData)
QResist.shared.validate(digest: fromServer, expectedDigest: onDevice, provider: "iCloud")
```

---

## Running the tests

```bash
swift test
```

---

## License

MIT — see [LICENSE](LICENSE).
