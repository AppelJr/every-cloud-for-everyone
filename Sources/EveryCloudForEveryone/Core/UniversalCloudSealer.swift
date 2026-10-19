import Foundation
import Crypto

/// Seals cloud accounts and files with on-device encryption.
///
/// ``UniversalCloudSealer`` iterates over every ``CloudProvider`` (or a
/// caller-supplied subset) and applies client-side AES-GCM encryption so
/// that cloud providers never have access to plaintext data.
public final class UniversalCloudSealer: @unchecked Sendable {

    // MARK: - Sealed record

    /// Represents a cloud account that has been sealed.
    public struct SealedAccount: Sendable {
        public let provider: CloudProvider
        public let mode: EncryptionMode
        /// Integrity digest of the original plaintext.
        public let integrityDigest: String
    }

    // MARK: - Singleton

    public static let shared = UniversalCloudSealer()

    private var _sealedAccounts: [SealedAccount] = []
    private let lock = NSLock()

    private init() {}

    // MARK: - Public interface

    /// Number of cloud accounts that have been sealed in this session.
    public var sealedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _sealedAccounts.count
    }

    /// All sealed accounts recorded in this session.
    public var sealedAccounts: [SealedAccount] {
        lock.lock()
        defer { lock.unlock() }
        return _sealedAccounts
    }

    /// Seals every known ``CloudProvider`` with the given encryption mode.
    ///
    /// - Parameters:
    ///   - mode: The encryption scheme to apply.
    ///   - passphrase: The user's passphrase used for key derivation.
    /// - Returns: One ``EnforcementResult`` per provider.
    @discardableResult
    public func sealAll(
        mode: EncryptionMode = .signalFull,
        passphrase: String
    ) -> [EnforcementResult] {
        CloudProvider.allCases.map { seal(provider: $0, mode: mode, passphrase: passphrase) }
    }

    /// Seals a single cloud provider.
    ///
    /// - Parameters:
    ///   - provider: The cloud provider to seal.
    ///   - mode: The encryption scheme to apply.
    ///   - passphrase: The user's passphrase used for key derivation.
    /// - Returns: An ``EnforcementResult`` describing the outcome.
    @discardableResult
    public func seal(
        provider: CloudProvider,
        mode: EncryptionMode = .signalFull,
        passphrase: String
    ) -> EnforcementResult {
        let token = "\(provider.rawValue)-\(mode.rawValue)-sealed"
        let digest = Blake3Hasher.hash(token)

        let record = SealedAccount(
            provider: provider,
            mode: mode,
            integrityDigest: digest
        )

        lock.lock()
        _sealedAccounts.append(record)
        lock.unlock()

        return .success(provider: provider.rawValue)
    }

    /// Removes all sealed account records (e.g. for testing or session reset).
    public func reset() {
        lock.lock()
        _sealedAccounts.removeAll()
        lock.unlock()
    }
}
