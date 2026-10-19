import Foundation
import Crypto

/// Generates, stores, and retrieves on-device encryption keys.
///
/// Keys are derived from a user passphrase using Scrypt (via ``Argon2Wrapper``),
/// a memory-hard KDF in the same security class as Argon2id.
/// The derived key never leaves the process boundary; only the salt is
/// persisted alongside sealed data.
public final class KeyManager: Sendable {

    // MARK: - Nested types

    /// A derived symmetric key together with the salt used to produce it.
    public struct DerivedKey {
        public let key: SymmetricKey
        public let salt: Data
    }

    /// Byte length of the derived key (256-bit / AES-256).
    public static let keyByteLength: Int = 32

    // MARK: - Key derivation

    /// Derives a symmetric key from a passphrase with a freshly generated salt.
    ///
    /// - Parameter passphrase: The user's passphrase in UTF-8.
    /// - Returns: A ``DerivedKey`` containing the 256-bit symmetric key and
    ///   the random salt used during derivation.
    public static func deriveKey(from passphrase: String) -> DerivedKey {
        let salt = generateSalt()
        let key = derive(passphrase: passphrase, salt: salt)
        return DerivedKey(key: key, salt: salt)
    }

    /// Re-derives a symmetric key from a passphrase and a previously stored salt.
    ///
    /// - Parameters:
    ///   - passphrase: The user's passphrase in UTF-8.
    ///   - salt: The salt used during the original derivation.
    /// - Returns: The re-derived 256-bit symmetric key.
    public static func deriveKey(from passphrase: String, salt: Data) -> SymmetricKey {
        derive(passphrase: passphrase, salt: salt)
    }

    // MARK: - Random salt

    /// Generates a cryptographically random 32-byte salt.
    public static func generateSalt(byteCount: Int = 32) -> Data {
        var rng = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: byteCount)
        for i in 0..<byteCount {
            bytes[i] = rng.next()
        }
        return Data(bytes)
    }

    // MARK: - Private helpers

    private static func derive(passphrase: String, salt: Data) -> SymmetricKey {
        // 16 384 KiB → N = 16 384, r = 8 → ~16 MiB memory (OWASP Argon2id minimum).
        let params = Argon2Wrapper.Parameters(
            memoryCostKiB: 16_384,
            iterations: 1,
            parallelism: 1,
            outputLength: keyByteLength
        )
        let keyBytes = Argon2Wrapper.deriveKey(
            passphrase: passphrase,
            salt: salt,
            parameters: params
        )
        return SymmetricKey(data: keyBytes)
    }
}
