import Foundation

/// A Gate-issued receipt must be supplied by the application authority adapter.
/// This protocol intentionally has no permissive default implementation.
public protocol ParallelCloudEgressAuthorizer: Sendable {
    func isAuthorized(taskID: String, plaintextDigest: String) async -> Bool
}

/// Produces ciphertext only. This type does not upload, sync, or open sockets.
public struct ParallelCloudSealResult: Sendable {
    public let taskID: String
    public let plaintextDigest: String
    public let ciphertext: Data
    public let salt: Data
}

/// Local sealing boundary for Parallel-12.
/// Callers must separately obtain Gate authorization; absence always denies.
public struct ParallelCloudSealingAdapter: Sendable {
    private let authorizer: any ParallelCloudEgressAuthorizer

    public init(authorizer: any ParallelCloudEgressAuthorizer) {
        self.authorizer = authorizer
    }

    public func sealForApprovedExport(
        taskID: String,
        plaintext: Data,
        passphrase: String
    ) async throws -> ParallelCloudSealResult {
        guard !taskID.isEmpty, !plaintext.isEmpty, !passphrase.isEmpty else {
            throw ParallelCloudSealingError.invalidInput
        }
        let digest = Self.sha256(plaintext)
        guard await authorizer.isAuthorized(taskID: taskID, plaintextDigest: digest) else {
            throw ParallelCloudSealingError.authorizationDenied
        }
        let sealed = try ContractEnforcer.shared.seal(plaintext: plaintext, passphrase: passphrase)
        return ParallelCloudSealResult(
            taskID: taskID,
            plaintextDigest: digest,
            ciphertext: sealed.sealed,
            salt: sealed.salt
        )
    }

    private static func sha256(_ data: Data) -> String {
        // Use the package's existing digest primitive; no transport is performed.
        Blake3Hasher.hash(data)
    }
}

public enum ParallelCloudSealingError: Error {
    case invalidInput
    case authorizationDenied
}
