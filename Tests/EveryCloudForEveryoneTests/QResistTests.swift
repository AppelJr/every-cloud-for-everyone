import XCTest
@testable import EveryCloudForEveryone

final class QResistTests: XCTestCase {

    override func setUp() {
        super.setUp()
        QResist.shared.reset()
    }

    // MARK: - Initial state

    func testInitialStateIsDisarmed() {
        XCTAssertEqual(QResist.shared.state, .disarmed)
    }

    func testIsNotTriggeredWhenDisarmed() {
        XCTAssertFalse(QResist.shared.isTriggered)
    }

    // MARK: - Arm / disarm

    func testArmChangesStateToArmed() {
        QResist.shared.arm()
        XCTAssertEqual(QResist.shared.state, .armed)
    }

    func testDisarmAfterArmChangesStateToDisarmed() {
        QResist.shared.arm()
        QResist.shared.disarm()
        XCTAssertEqual(QResist.shared.state, .disarmed)
    }

    // MARK: - Trigger

    func testTriggerSetsTriggeredState() {
        QResist.shared.trigger(provider: "iCloud", reason: "Hash mismatch")
        XCTAssertTrue(QResist.shared.isTriggered)
        XCTAssertEqual(QResist.shared.state, .triggered(provider: "iCloud", reason: "Hash mismatch"))
    }

    // MARK: - Digest validation

    func testMatchingDigestsReturnTrue() {
        QResist.shared.arm()
        let digest = Blake3Hasher.hash("my-cloud-data")
        let result = QResist.shared.validate(digest: digest, expectedDigest: digest, provider: "Dropbox")
        XCTAssertTrue(result)
        XCTAssertFalse(QResist.shared.isTriggered)
    }

    func testMismatchedDigestsTriggerKillSwitch() {
        QResist.shared.arm()
        let result = QResist.shared.validate(
            digest: "aabbcc",
            expectedDigest: "112233",
            provider: "OneDrive"
        )
        XCTAssertFalse(result)
        XCTAssertTrue(QResist.shared.isTriggered)
    }

    func testTriggerRecordsProviderName() {
        QResist.shared.validate(digest: "bad", expectedDigest: "good", provider: "Azure")
        if case .triggered(let provider, _) = QResist.shared.state {
            XCTAssertEqual(provider, "Azure")
        } else {
            XCTFail("Expected .triggered state")
        }
    }

    // MARK: - Reset

    func testResetReturnsToDisarmed() {
        QResist.shared.arm()
        QResist.shared.trigger(provider: "X", reason: "Y")
        QResist.shared.reset()
        XCTAssertEqual(QResist.shared.state, .disarmed)
    }
}
