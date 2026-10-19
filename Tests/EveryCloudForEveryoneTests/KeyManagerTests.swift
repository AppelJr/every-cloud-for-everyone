import XCTest
@testable import EveryCloudForEveryone

final class KeyManagerTests: XCTestCase {

    // MARK: - Key derivation

    func testDeriveKeyProduces256BitKey() {
        let derived = KeyManager.deriveKey(from: "my-passphrase")
        XCTAssertEqual(derived.key.bitCount, 256)
    }

    func testDeriveKeyProducesNonEmptySalt() {
        let derived = KeyManager.deriveKey(from: "my-passphrase")
        XCTAssertFalse(derived.salt.isEmpty)
    }

    func testSameSaltProducesSameKey() {
        let salt = KeyManager.generateSalt()
        let passphrase = "consistent-passphrase"
        let key1 = KeyManager.deriveKey(from: passphrase, salt: salt)
        let key2 = KeyManager.deriveKey(from: passphrase, salt: salt)
        XCTAssertEqual(
            key1.withUnsafeBytes { Data($0) },
            key2.withUnsafeBytes { Data($0) }
        )
    }

    func testDifferentSaltsProduceDifferentKeys() {
        let passphrase = "same-passphrase"
        let salt1 = KeyManager.generateSalt()
        let salt2 = KeyManager.generateSalt()
        let key1 = KeyManager.deriveKey(from: passphrase, salt: salt1)
        let key2 = KeyManager.deriveKey(from: passphrase, salt: salt2)
        XCTAssertNotEqual(
            key1.withUnsafeBytes { Data($0) },
            key2.withUnsafeBytes { Data($0) }
        )
    }

    func testDifferentPassphrasesProduceDifferentKeys() {
        let salt = KeyManager.generateSalt()
        let key1 = KeyManager.deriveKey(from: "passphrase-A", salt: salt)
        let key2 = KeyManager.deriveKey(from: "passphrase-B", salt: salt)
        XCTAssertNotEqual(
            key1.withUnsafeBytes { Data($0) },
            key2.withUnsafeBytes { Data($0) }
        )
    }

    // MARK: - Salt generation

    func testGeneratedSaltHasDefaultLength() {
        let salt = KeyManager.generateSalt()
        XCTAssertEqual(salt.count, 32)
    }

    func testGeneratedSaltWithCustomLength() {
        let salt = KeyManager.generateSalt(byteCount: 16)
        XCTAssertEqual(salt.count, 16)
    }

    func testTwoGeneratedSaltsAreDifferent() {
        let salt1 = KeyManager.generateSalt()
        let salt2 = KeyManager.generateSalt()
        XCTAssertNotEqual(salt1, salt2)
    }
}

final class Blake3HasherTests: XCTestCase {

    func testHashProducesNonEmptyString() {
        let hash = Blake3Hasher.hash("hello world")
        XCTAssertFalse(hash.isEmpty)
    }

    func testHashIsHexEncoded() {
        let hash = Blake3Hasher.hash("test")
        let hexChars = CharacterSet(charactersIn: "0123456789abcdef")
        XCTAssertTrue(hash.unicodeScalars.allSatisfy { hexChars.contains($0) })
    }

    func testSameInputProducesSameHash() {
        let h1 = Blake3Hasher.hash("deterministic")
        let h2 = Blake3Hasher.hash("deterministic")
        XCTAssertEqual(h1, h2)
    }

    func testDifferentInputsProduceDifferentHashes() {
        let h1 = Blake3Hasher.hash("apple")
        let h2 = Blake3Hasher.hash("orange")
        XCTAssertNotEqual(h1, h2)
    }

    func testVerifyReturnsTrueForMatchingHash() {
        let data = Data("verify me".utf8)
        let hash = Blake3Hasher.hash(data)
        XCTAssertTrue(Blake3Hasher.verify(data: data, expectedHex: hash))
    }

    func testVerifyReturnsFalseForMismatch() {
        let data = Data("original".utf8)
        XCTAssertFalse(Blake3Hasher.verify(data: data, expectedHex: "deadbeef"))
    }

    func testVerifyIsCaseInsensitive() {
        let data = Data("case".utf8)
        let lower = Blake3Hasher.hash(data)
        let upper = lower.uppercased()
        XCTAssertTrue(Blake3Hasher.verify(data: data, expectedHex: upper))
    }
}

final class Argon2WrapperTests: XCTestCase {

    func testDeriveKeyProducesExpectedLength() {
        let salt = KeyManager.generateSalt()
        let key = Argon2Wrapper.deriveKey(passphrase: "pass", salt: salt)
        XCTAssertEqual(key.count, Argon2Wrapper.Parameters.default.outputLength)
    }

    func testSameSaltAndPassphraseProducesSameKey() {
        let salt = KeyManager.generateSalt()
        let k1 = Argon2Wrapper.deriveKey(passphrase: "same", salt: salt)
        let k2 = Argon2Wrapper.deriveKey(passphrase: "same", salt: salt)
        XCTAssertEqual(k1, k2)
    }

    func testDifferentSaltsProduceDifferentKeys() {
        let k1 = Argon2Wrapper.deriveKey(passphrase: "pass", salt: Data("salt1".utf8))
        let k2 = Argon2Wrapper.deriveKey(passphrase: "pass", salt: Data("salt2".utf8))
        XCTAssertNotEqual(k1, k2)
    }

    func testDifferentPassphrasesProduceDifferentKeys() {
        let salt = Data("fixed-salt".utf8)
        let k1 = Argon2Wrapper.deriveKey(passphrase: "pass1", salt: salt)
        let k2 = Argon2Wrapper.deriveKey(passphrase: "pass2", salt: salt)
        XCTAssertNotEqual(k1, k2)
    }

    func testCustomOutputLength() {
        let params = Argon2Wrapper.Parameters(
            memoryCostKiB: 64,
            iterations: 1,
            parallelism: 1,
            outputLength: 64
        )
        let key = Argon2Wrapper.deriveKey(
            passphrase: "pass",
            salt: Data("salt".utf8),
            parameters: params
        )
        XCTAssertEqual(key.count, 64)
    }
}

final class LockdownModeTests: XCTestCase {

    override func setUp() {
        super.setUp()
        LockdownMode.shared.reset()
    }

    func testInitialStateIsInactive() {
        XCTAssertFalse(LockdownMode.shared.isActive)
    }

    func testActivateChangesState() {
        LockdownMode.shared.activate()
        XCTAssertTrue(LockdownMode.shared.isActive)
    }

    func testDeactivateChangesStateToInactive() {
        LockdownMode.shared.activate()
        LockdownMode.shared.deactivate()
        XCTAssertFalse(LockdownMode.shared.isActive)
    }

    func testResetDeactivates() {
        LockdownMode.shared.activate()
        LockdownMode.shared.reset()
        XCTAssertEqual(LockdownMode.shared.state, .inactive)
    }
}
