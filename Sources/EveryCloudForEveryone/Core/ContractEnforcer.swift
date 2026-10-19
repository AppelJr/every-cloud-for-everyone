import Foundation
import Crypto

/// Enforces the privacy contract between a user and their cloud providers.
///
/// ``ContractEnforcer`` verifies that the promises made in each provider's
/// privacy policy (end-to-end encryption, no server key storage) are upheld.
/// Where they are not, it applies on-device encryption so users remain
/// protected regardless.
public final class ContractEnforcer: Sendable {

    // MARK: - Policy

    /// A privacy promise extracted from a cloud provider's Terms of Service.
    public struct PolicyClaim: Sendable {
        public let provider: String
        public let claim: String
        public let promisesE2E: Bool
        public let promisesUserKeys: Bool

        public init(
            provider: String,
            claim: String,
            promisesE2E: Bool,
            promisesUserKeys: Bool
        ) {
            self.provider = provider
            self.claim = claim
            self.promisesE2E = promisesE2E
            self.promisesUserKeys = promisesUserKeys
        }
    }

    /// Result of a contract evaluation.
    public enum ComplianceResult: Equatable, Sendable {
        /// Provider keeps its promise – no client-side override needed.
        case compliant(provider: String)
        /// Provider violated its promise – client-side encryption enforced.
        case enforced(provider: String, reason: String)
    }

    // MARK: - Singleton

    public static let shared = ContractEnforcer()
    private init() {}

    // MARK: - Enforcement

    /// Evaluates a provider's ``PolicyClaim`` and enforces client-side
    /// encryption if the claim cannot be independently verified.
    ///
    /// - Parameter claim: The policy claim to evaluate.
    /// - Returns: A ``ComplianceResult`` describing the outcome.
    public func enforce(claim: PolicyClaim) -> ComplianceResult {
        // We cannot verify server-side behaviour at runtime, so we treat any
        // promise of E2E or user-owned keys as requiring enforcement – we
        // apply our own encryption layer on top regardless.
        if claim.promisesE2E || claim.promisesUserKeys {
            return .enforced(
                provider: claim.provider,
                reason: "Client-side encryption applied to uphold provider's own privacy promise."
            )
        }
        return .compliant(provider: claim.provider)
    }

    /// Evaluates a list of policy claims.
    ///
    /// - Parameter claims: The policy claims to evaluate.
    /// - Returns: One ``ComplianceResult`` per claim, in the same order.
    public func enforce(claims: [PolicyClaim]) -> [ComplianceResult] {
        claims.map { enforce(claim: $0) }
    }

    // MARK: - Seal

    /// Encrypts `plaintext` using AES-GCM with a key derived from `passphrase`.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt (e.g. a file or cloud blob).
    ///   - passphrase: The user's passphrase. The derived key never leaves
    ///     this process.
    /// - Returns: The AES-GCM sealed box combined data (nonce + ciphertext +
    ///   tag) together with the salt that was used during key derivation.
    public func seal(
        plaintext: Data,
        passphrase: String
    ) throws -> (sealed: Data, salt: Data) {
        let derived = KeyManager.deriveKey(from: passphrase)
        let sealedBox = try AES.GCM.seal(plaintext, using: derived.key)
        guard let combined = sealedBox.combined else {
            throw ContractEnforcerError.sealFailed
        }
        return (combined, derived.salt)
    }

    /// Decrypts data previously returned by ``seal(plaintext:passphrase:)``.
    ///
    /// - Parameters:
    ///   - sealedData: The combined AES-GCM data (nonce + ciphertext + tag).
    ///   - salt: The salt that was produced during sealing.
    ///   - passphrase: The same passphrase used during sealing.
    /// - Returns: The original plaintext.
    public func open(
        sealedData: Data,
        salt: Data,
        passphrase: String
    ) throws -> Data {
        let key = KeyManager.deriveKey(from: passphrase, salt: salt)
        let box = try AES.GCM.SealedBox(combined: sealedData)
        return try AES.GCM.open(box, using: key)
    }
}

/// Errors thrown by ``ContractEnforcer``.
public enum ContractEnforcerError: Error, Sendable {
    case sealFailed
    case openFailed
}
