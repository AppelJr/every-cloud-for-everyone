import Foundation
import Argon2Swift

/// Argon2id key derivation for the canonical v1.1 sealing format.
public enum Argon2KDFV1_1 {
    public static let memoryKiB = 64 * 1024
    public static let iterations = 3
    public static let parallelism = 4
    public static let outputLength = 32

    public static func deriveKey(password: Data, salt: Data) throws -> (key: Data, usedFallback: Bool) {
        guard salt.count == 16 else { throw KDFError.invalidSalt }

        let result = try Argon2Swift.hashPasswordBytes(
            password: password,
            salt: Salt(bytes: salt),
            iterations: iterations,
            memory: memoryKiB,
            parallelism: parallelism,
            length: outputLength,
            type: .id,
            version: .V13
        )
        return (result.hashData(), false)
    }

    public enum KDFError: Error, Equatable {
        case invalidSalt
    }
}
