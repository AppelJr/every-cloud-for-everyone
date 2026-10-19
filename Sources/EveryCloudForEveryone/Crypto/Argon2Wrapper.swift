import Foundation
import CryptoSwift

/// Memory-hard key derivation using Scrypt with an Argon2id-shaped parameter API.
///
/// Production target is native Argon2id via C interop. Current implementation
/// uses Scrypt (CryptoSwift) which provides equivalent memory-hardness for the
/// on-device sealing path.
public enum Argon2Wrapper {

    // MARK: - Parameters

    public struct Parameters: Sendable {
        /// Memory cost in kibibytes.
        public let memoryCostKiB: Int
        /// Number of iterations.
        public let iterations: Int
        /// Degree of parallelism.
        public let parallelism: Int
        /// Desired output key length in bytes.
        public let outputLength: Int

        /// Defaults giving ~16 MiB memory usage, 1 thread, 32-byte output.
        /// Equivalent N = 16 384, r = 8, p = 1 → memory = 128 × 16 384 × 8 ≈ 16 MiB.
        public static let `default` = Parameters(
            memoryCostKiB: 16_384,
            iterations: 1,
            parallelism: 1,
            outputLength: 32
        )
    }

    // MARK: - Derivation

    /// Derives a key from `passphrase` and `salt` using Scrypt.
    ///
    /// - Parameters:
    ///   - passphrase: The user's passphrase (UTF-8 encoded).
    ///   - salt: A random salt (must not be empty; ≥16 bytes recommended).
    ///   - parameters: Tuning parameters.
    /// - Returns: Raw key bytes of length `parameters.outputLength`.
    public static func deriveKey(
        passphrase: String,
        salt: Data,
        parameters: Parameters = .default
    ) -> Data {
        precondition(!salt.isEmpty, "Argon2Wrapper: salt must not be empty.")
        precondition(parameters.outputLength > 0, "Argon2Wrapper: outputLength must be > 0.")
        precondition(parameters.parallelism > 0, "Argon2Wrapper: parallelism must be > 0.")

        // Scrypt N must be ≥ 2 and a power of two.
        // We derive it from memoryCostKiB so callers can reason in KiB terms.
        // Memory = 128 × N × r bytes  (r fixed at 8 below).
        let n = nearestPowerOfTwo(lessThanOrEqualTo: max(2, parameters.memoryCostKiB))

        let scrypt: Scrypt
        do {
            // r = 8 is the standard recommendation and is used throughout
            // the Scrypt literature; it keeps the memory formula simple.
            scrypt = try Scrypt(
                password: Array(passphrase.utf8),
                salt: Array(salt),
                dkLen: parameters.outputLength,
                N: n,
                r: 8,
                p: parameters.parallelism
            )
        } catch {
            preconditionFailure("Argon2Wrapper: Scrypt initialisation failed – \(error).")
        }

        do {
            return Data(try scrypt.calculate())
        } catch {
            preconditionFailure("Argon2Wrapper: Scrypt calculation failed – \(error).")
        }
    }

    // MARK: - Private helpers

    /// Returns the largest power of two that is ≤ `value`.
    private static func nearestPowerOfTwo(lessThanOrEqualTo value: Int) -> Int {
        var n = 1
        while n * 2 <= value { n *= 2 }
        return n
    }
}
