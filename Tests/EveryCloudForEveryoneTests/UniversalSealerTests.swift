import XCTest
@testable import EveryCloudForEveryone

final class UniversalSealerTests: XCTestCase {

    override func setUp() {
        super.setUp()
        UniversalCloudSealer.shared.reset()
    }

    // MARK: - Seal all providers

    func testSealAllReturnsOneResultPerProvider() {
        let results = UniversalCloudSealer.shared.sealAll(passphrase: "test-passphrase")
        XCTAssertEqual(results.count, CloudProvider.allCases.count)
    }

    func testSealAllResultsAreAllSuccesses() {
        let results = UniversalCloudSealer.shared.sealAll(passphrase: "test-passphrase")
        for result in results {
            XCTAssertTrue(result.isSuccess, "Expected .success but got \(result)")
        }
    }

    func testSealAllCountMatchesAllProviders() {
        UniversalCloudSealer.shared.sealAll(passphrase: "test-passphrase")
        XCTAssertEqual(UniversalCloudSealer.shared.sealedCount, CloudProvider.allCases.count)
    }

    // MARK: - Seal single provider

    func testSealSingleProviderSucceeds() {
        let result = UniversalCloudSealer.shared.seal(
            provider: .iCloud,
            mode: .signalFull,
            passphrase: "test-passphrase"
        )
        XCTAssertEqual(result, .success(provider: CloudProvider.iCloud.rawValue))
    }

    func testSealedAccountHasCorrectProvider() {
        UniversalCloudSealer.shared.seal(provider: .protonDrive, mode: .signalFull, passphrase: "pw")
        let accounts = UniversalCloudSealer.shared.sealedAccounts
        XCTAssertTrue(accounts.contains { $0.provider == .protonDrive })
    }

    func testSealedAccountHasNonEmptyIntegrityDigest() {
        UniversalCloudSealer.shared.seal(provider: .dropbox, mode: .pgpSignalHybrid, passphrase: "pw")
        let accounts = UniversalCloudSealer.shared.sealedAccounts
        XCTAssertTrue(accounts.allSatisfy { !$0.integrityDigest.isEmpty })
    }

    func testSealedAccountRecordsEncryptionMode() {
        UniversalCloudSealer.shared.seal(provider: .nextcloud, mode: .pgpWeb, passphrase: "pw")
        let accounts = UniversalCloudSealer.shared.sealedAccounts
        XCTAssertTrue(accounts.contains { $0.mode == .pgpWeb })
    }

    // MARK: - Reset

    func testResetClearsSealedAccounts() {
        UniversalCloudSealer.shared.sealAll(passphrase: "test-passphrase")
        XCTAssertGreaterThan(UniversalCloudSealer.shared.sealedCount, 0)
        UniversalCloudSealer.shared.reset()
        XCTAssertEqual(UniversalCloudSealer.shared.sealedCount, 0)
    }

    // MARK: - Cloud provider coverage

    func testAllCasesSealed() {
        UniversalCloudSealer.shared.sealAll(passphrase: "test-passphrase")
        let sealedProviders = Set(UniversalCloudSealer.shared.sealedAccounts.map { $0.provider })
        let allProviders = Set(CloudProvider.allCases)
        XCTAssertEqual(sealedProviders, allProviders)
    }
}
