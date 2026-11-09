import Foundation
import Crypto

/// Canonical metadata for a v1 AES-256-GCM sealed blob.
public struct SealRecord: Equatable, Sendable {
    public let algorithm: String
    public let blobSHA256: String
    public let keyID: String
    public let nonce: String
    public let provider: String
    public let salt: String
    public let sealedAt: String
    public let version: Int

    public init(blobSHA256: String, keyID: String, nonce: String,
                provider: String, salt: String, sealedAt: String) throws {
        guard blobSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              !keyID.isEmpty, !provider.isEmpty,
              let nonceData = Data(base64Encoded: nonce), nonceData.count == 12,
              let saltData = Data(base64Encoded: salt), saltData.count == 16,
              !sealedAt.isEmpty else { throw SealError.invalidRecord }
        self.algorithm = "AES-256-GCM"
        self.blobSHA256 = blobSHA256
        self.keyID = keyID
        self.nonce = nonce
        self.provider = provider
        self.salt = salt
        self.sealedAt = sealedAt
        self.version = 1
    }

    public func canonicalJSON() throws -> String {
        // JSONEncoder's sorted-key mode gives deterministic escaping and key order.
        let object: [String: Any] = [
            "algorithm": algorithm, "blob_sha256": blobSHA256, "key_id": keyID,
            "nonce": nonce, "provider": provider, "salt": salt,
            "sealed_at": sealedAt, "version": version
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed])
        guard let value = String(data: data, encoding: .utf8) else { throw SealError.invalidRecord }
        return value
    }

    public static func decodeCanonical(_ data: Data) throws -> SealRecord {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["algorithm","blob_sha256","key_id","nonce","provider","salt","sealed_at","version"]),
              let algorithm = object["algorithm"] as? String, algorithm == "AES-256-GCM",
              let digest = object["blob_sha256"] as? String,
              let keyID = object["key_id"] as? String,
              let nonce = object["nonce"] as? String,
              let provider = object["provider"] as? String,
              let salt = object["salt"] as? String,
              let sealedAt = object["sealed_at"] as? String,
              let version = object["version"] as? Int, version == 1 else {
            throw SealError.invalidRecord
        }
        let record = try SealRecord(blobSHA256: digest, keyID: keyID, nonce: nonce,
                                    provider: provider, salt: salt, sealedAt: sealedAt)
        guard try record.canonicalJSON() == String(decoding: data, as: UTF8.self) else {
            throw SealError.nonCanonicalRecord
        }
        return record
    }
}

public enum SealError: Error, Equatable {
    case invalidRecord
    case nonCanonicalRecord
    case unsupportedProvider
    case invalidBlob
    case integrityFailure
    case lockdown
}

public protocol NetworkBoundaryV1_1: AnyObject {
    var isDenied: Bool { get }
    func deny(reason: String)
}

/// In-memory boundary for tests and embedding. Production must provide an OS/network
/// enforcement implementation; this object alone cannot block device networking.
public final class InMemoryNetworkBoundaryV1_1: NetworkBoundaryV1_1 {
    private let lock = NSLock()
    private var denied = false
    public init() {}
    public var isDenied: Bool { lock.lock(); defer { lock.unlock() }; return denied }
    public func deny(reason: String) { lock.lock(); denied = true; lock.unlock() }
}

public final class UniversalCloudSealerV1_1 {
    public struct Sealed: Sendable {
        public let ciphertext: Data
        public let tag: Data
        public let nonce: Data
        public let salt: Data
        public let record: SealRecord
    }

    public struct SCAR: Sendable {
        public let eventType: String
        public let provider: String
        public let reason: String
    }

    private let networkBoundary: NetworkBoundaryV1_1
    private(set) public var isLockdownActive = false
    private(set) public var scar: [SCAR] = []

    public init(networkBoundary: NetworkBoundaryV1_1 = InMemoryNetworkBoundaryV1_1()) {
        self.networkBoundary = networkBoundary
    }

    public func seal(plaintext: Data, password: String, provider: String) throws -> Sealed {
        guard provider == "Local" else { throw SealError.unsupportedProvider }
        guard !isLockdownActive else { throw SealError.lockdown }
        let salt = Self.random(count: 16)
        let nonce = Self.random(count: 12)
        let key = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: salt).key
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key),
                                   nonce: AES.GCM.Nonce(data: nonce))
        let blob = Data(box.ciphertext) + Data(box.tag)
        let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
        let record = try SealRecord(blobSHA256: digest, keyID: "password-derived-v1",
                                    nonce: nonce.base64EncodedString(), provider: provider,
                                    salt: salt.base64EncodedString(),
                                    sealedAt: ISO8601DateFormatter().string(from: Date()))
        return Sealed(ciphertext: Data(box.ciphertext), tag: Data(box.tag),
                      nonce: nonce, salt: salt, record: record)
    }

    public static func verifyWithPassword(password: String, blob: Data, record: SealRecord) throws -> Data {
        let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
        guard digest == record.blobSHA256 else { throw SealError.integrityFailure }
        guard let nonceData = Data(base64Encoded: record.nonce),
              let saltData = Data(base64Encoded: record.salt), blob.count >= 16 else {
            throw SealError.invalidBlob
        }
        let key = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: saltData).key
        let ciphertext = blob.dropLast(16)
        let tag = blob.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData),
                                        ciphertext: Data(ciphertext), tag: Data(tag))
        return try AES.GCM.open(box, using: SymmetricKey(data: key))
    }

    public func qresist(provider: String, reason: String) throws {
        scar.append(SCAR(eventType: "INTEGRITY_FAILURE", provider: provider, reason: reason))
        networkBoundary.deny(reason: reason)
    }

    public func lockdown() throws { isLockdownActive = true; networkBoundary.deny(reason: "lockdown") }
    public func capabilityAllowed(_ capability: String) -> Bool {
        if isLockdownActive { return capability == "local_vault" }
        return capability != "external_upload" || !networkBoundary.isDenied
    }

    private static func random(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}
