import Foundation

public protocol NetworkBoundaryV1_1: AnyObject, Sendable {
    func denyAll()
}

public final class InMemoryNetworkBoundaryV1_1: NetworkBoundaryV1_1, @unchecked Sendable {
    private let lock = NSLock()
    private var denied = false

    public init() {}

    public var isDenied: Bool {
        lock.lock(); defer { lock.unlock() }
        return denied
    }

    public func denyAll() {
        lock.lock(); denied = true; lock.unlock()
    }
}
