import XCTest
@testable import EveryCloudForEveryone

private struct TestParallelAuthorizer: ParallelCloudEgressAuthorizer {
    let allowed: Bool
    func isAuthorized(taskID: String, plaintextDigest: String) async -> Bool {
        allowed && !taskID.isEmpty && plaintextDigest.count == 64
    }
}

final class ParallelCloudSealingAdapterTests: XCTestCase {
    func testMissingGateAuthorizationDeniesSealing() async {
        let adapter = ParallelCloudSealingAdapter(authorizer: TestParallelAuthorizer(allowed: false))
        do {
            _ = try await adapter.sealForApprovedExport(
                taskID: "task-1",
                plaintext: Data("private".utf8),
                passphrase: "test-passphrase"
            )
            XCTFail("sealing must be denied without Gate authorization")
        } catch ParallelCloudSealingError.authorizationDenied {
            // Expected fail-closed result.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testAuthorizedSealingReturnsCiphertextOnly() async throws {
        let plaintext = Data("private payload".utf8)
        let adapter = ParallelCloudSealingAdapter(authorizer: TestParallelAuthorizer(allowed: true))
        let result = try await adapter.sealForApprovedExport(
            taskID: "task-1",
            plaintext: plaintext,
            passphrase: "test-passphrase"
        )
        XCTAssertEqual(result.taskID, "task-1")
        XCTAssertEqual(result.plaintextDigest.count, 64)
        XCTAssertNotEqual(result.ciphertext, plaintext)
        XCTAssertFalse(result.salt.isEmpty)
    }
}
