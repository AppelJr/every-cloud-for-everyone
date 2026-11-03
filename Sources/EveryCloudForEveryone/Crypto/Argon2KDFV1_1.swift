import Foundation
import CryptoSwift
#if canImport(Argon2)
import Argon2
#endif

public enum Argon2KDFV1_1 {
    public static let memoryKiB = 64 * 1024
    public static let iterations = 3
    public static let parallelism = 4
    public static let outputLength = 32

    public static func deriveKey(password: Data, salt: Data) throws -> (key: Data, usedFallback: Bool) {
        guard salt.count == 16 else { throw KDFError.invalidSalt }
        #if canImport(Argon2)
        let key = try Argon2.hash(password: password, salt: salt, iterations: iterations,
                                  memory: memoryKiB, parallelism: parallelism,
                                  outputLength: outputLength, variant: .id)
        return (key, false)
        #else
        let key = Data(SHA3(variant: .sha512).calculate(Array(password + salt))).prefix(outputLength)
        return (Data(key), true)
        #endif
    }

    public enum KDFError: Error, Equatable {
        case invalidSalt
    }
}
