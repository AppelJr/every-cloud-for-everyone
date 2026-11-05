import Foundation

/// Production outbound HTTPS transport.
/// Network access is enabled at initialization. Explicit lockdown invalidates
/// the active session and rejects subsequent requests.
public protocol NetworkBoundaryV1_1: AnyObject, Sendable {
    var isDenied: Bool { get }
    func allowAll()
    func denyAll()
    func execute(_ request: URLRequest) async throws -> (Data, URLResponse)
}

public final class URLSessionNetworkBoundaryV1_1: NetworkBoundaryV1_1, @unchecked Sendable {
    private let lock = NSLock()
    private let configuration: URLSessionConfiguration
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
        self.configuration = config
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
        session = URLSession(configuration: configuration)
    }

    public func denyAll() {
        lock.lock()
        denied = true
        let activeSession = session
        lock.unlock()
        activeSession.invalidateAndCancel()
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url,
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else {
            throw NetworkBoundaryError.invalidDestination
        }

        // Snapshot under a synchronous lock helper. Never hold a thread lock
        // across suspension; lockdown invalidates this session and cancels I/O.
        let activeSession = try sessionForRequest()
        return try await activeSession.data(for: request)
    }

    private func sessionForRequest() throws -> URLSession {
        lock.lock()
        defer { lock.unlock() }
        guard !denied else { throw NetworkBoundaryError.lockdownActive }
        return session
    }
}

public enum NetworkBoundaryError: Error, Equatable {
    case invalidDestination
    case lockdownActive
}
