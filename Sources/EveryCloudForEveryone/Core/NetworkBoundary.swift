import Foundation

/// Production outbound HTTP transport. Requests are allowed by default.
/// Lockdown cancels the active URLSession and rejects subsequent requests.
/// Only HTTPS destinations are accepted; TLS validation remains URLSession's default.
public protocol NetworkBoundaryV1_1: AnyObject, Sendable {
    var isDenied: Bool { get }
    func allowAll()
    func denyAll()
    func execute(_ request: URLRequest) async throws -> (Data, URLResponse)
}

public final class URLSessionNetworkBoundaryV1_1: NetworkBoundaryV1_1, @unchecked Sendable {
    private let lock = NSLock()
    private var denied = false
    private var session: URLSession

    public init(configuration: URLSessionConfiguration = .ephemeral) {
        let config = configuration.copy() as! URLSessionConfiguration
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 300
        self.session = URLSession(configuration: config)
    }

    public var isDenied: Bool {
        lock.lock()
        defer { lock.unlock() }
        return denied
    }

    public func allowAll() {
        lock.lock()
        defer { lock.unlock() }
        guard denied else { return }
        denied = false
        session = URLSession(configuration: .ephemeral)
    }

    public func denyAll() {
        lock.lock()
        denied = true
        let active = session
        lock.unlock()
        active.invalidateAndCancel()
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url,
              url.scheme?.lowercased() == "https",
              url.host?.isEmpty == false else {
            throw NetworkBoundaryError.invalidDestination
        }

        let activeSession: URLSession
        lock.lock()
        defer { lock.unlock() }
        guard !denied else { throw NetworkBoundaryError.lockdownActive }
        activeSession = session
        return try await activeSession.data(for: request)
    }
}

public enum NetworkBoundaryError: Error, Equatable {
    case invalidDestination
    case lockdownActive
}
