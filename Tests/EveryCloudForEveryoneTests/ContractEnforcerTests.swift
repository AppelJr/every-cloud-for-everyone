import XCTest
@testable import EveryCloudForEveryone

final class ContractEnforcerTests: XCTestCase {

    private let enforcer = ContractEnforcer.shared

    // MARK: - Policy evaluation

    func testProviderWithE2EPromiseIsEnforced() {
        let claim = ContractEnforcer.PolicyClaim(
            provider: "iCloud",
            claim: "End-to-end encryption so only you and the recipient can read your data.",
            promisesE2E: true,
            promisesUserKeys: false
        )
        let result = enforcer.enforce(claim: claim)
        if case .enforced(let provider, _) = result {
            XCTAssertEqual(provider, "iCloud")
        } else {
            XCTFail("Expected .enforced, got \(result)")
        }
    }

    func testProviderWithUserKeyPromiseIsEnforced() {
        let claim = ContractEnforcer.PolicyClaim(
            provider: "Google Drive",
            claim: "Your data is stored with user-owned keys.",
            promisesE2E: false,
            promisesUserKeys: true
        )
        let result = enforcer.enforce(claim: claim)
        XCTAssertEqual(result, .enforced(provider: "Google Drive", reason: "Client-side encryption applied to uphold provider's own privacy promise."))
    }

    func testProviderWithNoPrivacyClaimsIsCompliant() {
        let claim = ContractEnforcer.PolicyClaim(
            provider: "AcmeDrive",
            claim: "We store your data securely on our servers.",
            promisesE2E: false,
            promisesUserKeys: false
        )
        let result = enforcer.enforce(claim: claim)
        XCTAssertEqual(result, .compliant(provider: "AcmeDrive"))
    }

    func testBatchEnforcementReturnsOneResultPerClaim() {
        let claims: [ContractEnforcer.PolicyClaim] = [
            .init(provider: "iCloud",   claim: "", promisesE2E: true,  promisesUserKeys: false),
            .init(provider: "Dropbox",  claim: "", promisesE2E: false, promisesUserKeys: true),
            .init(provider: "AcmeDrive",claim: "", promisesE2E: false, promisesUserKeys: false)
        ]
        let results = enforcer.enforce(claims: claims)
        XCTAssertEqual(results.count, 3)

        // Detailed checks
        XCTAssertEqual(results[0], .enforced(provider: "iCloud",   reason: "Client-side encryption applied to uphold provider's own privacy promise."))
        XCTAssertEqual(results[1], .enforced(provider: "Dropbox",  reason: "Client-side encryption applied to uphold provider's own privacy promise."))
        XCTAssertEqual(results[2], .compliant(provider: "AcmeDrive"))
    }

    // MARK: - Seal / open round-trip

    func testSealAndOpenRoundTrip() throws {
        let plaintext = Data("Every customer. Every cloud.".utf8)
        let passphrase = "fortress-passphrase-2025"

        let (sealed, salt) = try enforcer.seal(plaintext: plaintext, passphrase: passphrase)
        XCTAssertFalse(sealed.isEmpty)

        let recovered = try enforcer.open(sealedData: sealed, salt: salt, passphrase: passphrase)
        XCTAssertEqual(recovered, plaintext)
    }

    func testOpenWithWrongPassphraseFails() throws {
        let plaintext = Data("Secret file".utf8)
        let (sealed, salt) = try enforcer.seal(plaintext: plaintext, passphrase: "correct-passphrase")

        XCTAssertThrowsError(
            try enforcer.open(sealedData: sealed, salt: salt, passphrase: "wrong-passphrase")
        )
    }

    func testSealProducesDifferentCiphertextEachTime() throws {
        let plaintext = Data("Same plaintext".utf8)
        let passphrase = "same-passphrase"

        let (sealed1, _) = try enforcer.seal(plaintext: plaintext, passphrase: passphrase)
        let (sealed2, _) = try enforcer.seal(plaintext: plaintext, passphrase: passphrase)

        // Different salts → different keys → different ciphertext
        XCTAssertNotEqual(sealed1, sealed2)
    }
}
