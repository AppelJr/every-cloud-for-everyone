import Foundation
import Crypto

/// Canonical Universal Cloud Sealer v1.1 implementation.
/// Local cryptographic sealing is independent from identity, authority and network I/O.
public final class UniversalCloudSealerV1_1: @unchecked Sendable {
    public let scar: SCARLedgerV1_1
    public let networkBoundary: NetworkBoundaryV1_1
    private var lockdownActive = false
    private let stateLock = NSLock()

    public init(scar: SCARLedgerV1_1 = SCARLedgerV1_1(),
                networkBoundary: NetworkBoundaryV1_1 = InMemoryNetworkBoundaryV1_1()) {
        self.scar = scar
        self.networkBoundary = networkBoundary
    }

    public var isLockdownActive: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return lockdownActive
    }

    public func capabilityAllowed(_ operation: String) -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        guard lockdownActive else { return true }
        return operation == "local_vault" || operation == "audit"
    }

    public func lockdown() throws {
        stateLock.lock(); lockdownActive = true; stateLock.unlock()
        networkBoundary.denyAll()
        _ = try scar.append(eventType: "LOCKDOWN_ENABLED", provider: "Local",
                            reason: "explicit_lockdown", action: "DENY_EXTERNAL_NETWORK")
    }

    /// Generates a fresh 16-byte salt and 12-byte nonce for every seal.
    public func seal(plaintext: Data, password: String, provider: String,
                     keyID: String = "default") throws -> (blob: Data, record: SealRecord) {
        guard ProviderPolicyV1_1.allows(provider) else { throw SealerError.providerBlocked(provider) }

        let salt = try randomBytes(count: 16)
        let nonce = try randomBytes(count: 12)
        let derived = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: salt)
        var key = [UInt8](derived.key)
        defer { key.zeroize() }

        if derived.usedFallback {
            _ = try scar.append(eventType: "KDF_FALLBACK", provider: provider,
                                reason: "argon2id_unavailable", action: "USE_SHA3_512_TRUNCATED")
        }

        let sealedBox = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key),
                                         nonce: AES.GCM.Nonce(data: nonce))
        guard let blob = sealedBox.combined else { throw SealerError.missingCombinedCiphertext }
        let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
        let record = try SealRecord(blobSHA256: digest, keyID: keyID,
                                    nonce: nonce.base64EncodedString(), provider: provider,
                                    salt: salt.base64EncodedString(), sealedAt: SCARLedgerV1_1.utcTimestamp())
        return (blob, record)
    }

    public func verify(blob: Data, record: SealRecord, password: String) throws -> Data {
        guard ProviderPolicyV1_1.allows(record.provider) else {
            throw SealerError.providerBlocked(record.provider)
        }
        do {
            let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
            guard digest == record.blobSHA256 else {
                try qresist(provider: record.provider, reason: "blob_hash_mismatch")
                throw SealerError.blobHashMismatch
            }
            guard let salt = Data(base64Encoded: record.salt), salt.count == 16,
                  let nonce = Data(base64Encoded: record.nonce), nonce.count == 12 else {
                throw SealerError.invalidRecord
            }
            let derived = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: salt)
            var key = [UInt8](derived.key)
            defer { key.zeroize() }
            if derived.usedFallback {
                _ = try scar.append(eventType: "KDF_FALLBACK", provider: record.provider,
                                    reason: "argon2id_unavailable", action: "USE_SHA3_512_TRUNCATED")
            }
            let sealedBox = try AES.GCM.SealedBox(combined: blob)
            return try AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
        } catch {
            if case SealerError.blobHashMismatch = error { throw error }
            try qresist(provider: record.provider,
                        reason: "decrypt_failure:\(String(describing: type(of: error)))")
            throw error
        }
    }

    /// Stateless verifier for cross-port interoperability.
    public static func verifyWithPassword(password: String, blob: Data,
                                          record: SealRecord) throws -> Data {
        let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
        guard digest == record.blobSHA256 else { throw SealerError.blobHashMismatch }
        guard let salt = Data(base64Encoded: record.salt), salt.count == 16,
              let nonce = Data(base64Encoded: record.nonce), nonce.count == 12 else {
            throw SealerError.invalidRecord
        }
        let derived = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: salt)
        var key = [UInt8](derived.key)
        defer { key.zeroize() }
        let sealedBox = try AES.GCM.SealedBox(combined: blob)
        return try AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
    }

    public func qresist(provider: String, reason: String) throws {
        networkBoundary.denyAll()
        _ = try scar.append(eventType: "INTEGRITY_FAILURE", provider: provider,
                            reason: reason, action: "WIPE_KEY_AND_DENY_NETWORK")
    }

    private func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for index in bytes.indices { bytes[index] = generator.next() }
        return Data(bytes)
    }
}

public enum SealerError: Error, Equatable {
    case providerBlocked(String)
    case blobHashMismatch
    case invalidRecord
    case missingCombinedCiphertext
}

private extension Array where Element == UInt8 {
    mutating func zeroize() { for index in indices { self[index] = 0 } }
}
