import Foundation

/// Canonical persisted metadata for Universal Cloud Sealer v1.1.
public struct SealRecord: Codable, Sendable, Equatable {
    public static let version = 1
    public static let algorithm = "AES-256-GCM"

    public let algorithm: String
    public let blobSHA256: String
    public let keyID: String
    public let nonce: String
    public let provider: String
    public let salt: String
    public let sealedAt: String
    public let version: Int

    public init(
        algorithm: String = SealRecord.algorithm,
        blobSHA256: String,
        keyID: String,
        nonce: String,
        provider: String,
        salt: String,
        sealedAt: String,
        version: Int = SealRecord.version
    ) throws {
        guard version == Self.version, algorithm == Self.algorithm else {
            throw SealRecordError.unsupportedVersionOrAlgorithm
        }
        guard Data(base64Encoded: salt)?.count == 16 else {
            throw SealRecordError.invalidSalt
        }
        guard Data(base64Encoded: nonce)?.count == 12 else {
            throw SealRecordError.invalidNonce
        }
        guard blobSHA256.count == 64, blobSHA256.allSatisfy({ $0.isHexDigit && $0.isLowercaseHex }) else {
            throw SealRecordError.invalidDigest
        }
        self.algorithm = algorithm
        self.blobSHA256 = blobSHA256
        self.keyID = keyID
        self.nonce = nonce
        self.provider = provider
        self.salt = salt
        self.sealedAt = sealedAt
        self.version = version
    }

    public func canonicalJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard let value = String(data: data, encoding: .utf8) else {
            throw SealRecordError.encodingFailed
        }
        return value
    }

    public static func decodeCanonical(_ data: Data) throws -> SealRecord {
        let raw = try JSONSerialization.jsonObject(with: data, options: [])
        guard let object = raw as? [String: Any] else { throw SealRecordError.invalidFieldSet }
        let expected: Set<String> = ["algorithm", "blob_sha256", "key_id", "nonce", "provider", "salt", "sealed_at", "version"]
        guard Set(object.keys) == expected else { throw SealRecordError.invalidFieldSet }
        return try JSONDecoder().decode(SealRecord.self, from: data)
    }

    enum CodingKeys: String, CodingKey {
        case algorithm
        case blobSHA256 = "blob_sha256"
        case keyID = "key_id"
        case nonce
        case provider
        case salt
        case sealedAt = "sealed_at"
        case version
    }
}

public enum SealRecordError: Error, Equatable {
    case unsupportedVersionOrAlgorithm
    case invalidSalt
    case invalidNonce
    case invalidDigest
    case invalidFieldSet
    case encodingFailed
}

private extension Character {
    var isHexDigit: Bool {
        switch self { case "0"..."9", "a"..."f", "A"..."F": return true; default: return false }
    }
    var isLowercaseHex: Bool {
        switch self { case "0"..."9", "a"..."f": return true; default: return false }
    }
}
