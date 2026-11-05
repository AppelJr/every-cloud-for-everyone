import Foundation
import XCTest
import Crypto
@testable import EveryCloudForEveryone

final class UniversalCloudSealerV1_1Tests: XCTestCase {
    func testCanonicalCrossPortVector() throws {
        let password = "cross-port-password"
        let salt = Data([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
        let nonce = Data([0xfe,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44])
        let plaintext = Data("cross-port interoperability".utf8)

        let derived = try Argon2KDFV1_1.deriveKey(password: Data(password.utf8), salt: salt).key
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: derived), nonce: AES.GCM.Nonce(data: nonce))
        let blob = try XCTUnwrap(sealed.combined)
        let digest = SHA256.hash(data: blob).map { String(format: "%02x", $0) }.joined()
        let record = try SealRecord(blobSHA256: digest, keyID: "vector-key",
                                    nonce: nonce.base64EncodedString(), provider: "Local",
                                    salt: salt.base64EncodedString(), sealedAt: "2026-01-01T00:00:00Z")

        XCTAssertEqual(blob.base64EncodedString(), "+aXZbLoL5cWIXs/kCuey+UTGcp8Twji6/KqqpiHaGyFXiEhLEiFKn9rXtQ==")
        XCTAssertEqual(record.blobSHA256, "74fdfd61f3eea62c7c4e90320e2624ec2ea1e32aeb3d719dc544170314102bac")
        XCTAssertEqual(try record.canonicalJSON(), "{\"algorithm\":\"AES-256-GCM\",\"blob_sha256\":\"74fdfd61f3eea62c7c4e90320e2624ec2ea1e32aeb3d719dc544170314102bac\",\"key_id\":\"vector-key\",\"nonce\":\"/u7dzLuqmYh3ZlVE\",\"provider\":\"Local\",\"salt\":\"ABEiM0RVZneImaq7zN3u/w==\",\"sealed_at\":\"2026-01-01T00:00:00Z\",\"version\":1}")
        XCTAssertEqual(try UniversalCloudSealerV1_1.verifyWithPassword(password: password, blob: blob, record: record), plaintext)
    }

    func testBlockedAndUnknownProvidersFailClosed() throws {
        let sealer = UniversalCloudSealerV1_1()
        XCTAssertThrowsError(try sealer.seal(plaintext: Data(), password: "p", provider: "Google"))
        XCTAssertThrowsError(try sealer.seal(plaintext: Data(), password: "p", provider: "Unknown"))
    }

    func testQResistAndLockdownDenyNetwork() throws {
        let boundary = InMemoryNetworkBoundaryV1_1()
        let sealer = UniversalCloudSealerV1_1(networkBoundary: boundary)
        try sealer.qresist(provider: "Local", reason: "tamper")
        XCTAssertTrue(boundary.isDenied)
        XCTAssertEqual(sealer.scar.snapshot.last?.eventType, "INTEGRITY_FAILURE")

        try sealer.lockdown()
        XCTAssertTrue(sealer.isLockdownActive)
        XCTAssertFalse(sealer.capabilityAllowed("external_upload"))
        XCTAssertTrue(sealer.capabilityAllowed("local_vault"))
    }
}
