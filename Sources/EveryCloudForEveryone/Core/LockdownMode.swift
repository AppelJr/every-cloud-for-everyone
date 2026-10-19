import Foundation

/// Puts the device into a hardened privacy mode, blocking all non-essential
/// network traffic and enforcing strict permission policies.
public final class LockdownMode: @unchecked Sendable {

    // MARK: - State

    public enum State: Equatable, Sendable {
        case inactive
        case active
    }

    // MARK: - Singleton

    public static let shared = LockdownMode()

    private var _state: State = .inactive
    private let lock = NSLock()

    private init() {}

    // MARK: - Interface

    /// Whether lockdown is currently active.
    public var state: State {
        lock.lock()
        defer { lock.unlock() }
        return _state
    }

    public var isActive: Bool { state == .active }

    /// Activates lockdown mode.
    public func activate() {
        lock.lock()
        _state = .active
        lock.unlock()
    }

    /// Deactivates lockdown mode (e.g. after user confirms recovery).
    public func deactivate() {
        lock.lock()
        _state = .inactive
        lock.unlock()
    }

    /// Resets to `.inactive` (used in tests / session teardown).
    public func reset() {
        lock.lock()
        _state = .inactive
        lock.unlock()
    }
}
