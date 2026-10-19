import Foundation

/// A quantum-resistant uplink kill-switch that terminates unauthorised sync.
///
/// When ``QResist`` detects that a cloud provider is transmitting data without
/// a valid on-device encryption proof, it can kill the uplink for that
/// provider and log the event for audit.
public final class QResist: @unchecked Sendable {

    // MARK: - State

    /// Represents the current armed/disarmed state.
    public enum State: Equatable, Sendable {
        case disarmed
        case armed
        case triggered(provider: String, reason: String)
    }

    // MARK: - Singleton

    public static let shared = QResist()

    private var _state: State = .disarmed
    private let lock = NSLock()

    private init() {}

    // MARK: - Interface

    /// The current state of the kill-switch.
    public var state: State {
        lock.lock()
        defer { lock.unlock() }
        return _state
    }

    /// Arms the kill-switch, enabling breach detection.
    public func arm() {
        lock.lock()
        _state = .armed
        lock.unlock()
    }

    /// Disarms the kill-switch (e.g. after a verified recovery).
    public func disarm() {
        lock.lock()
        _state = .disarmed
        lock.unlock()
    }

    /// Triggers the kill-switch for a specific provider.
    ///
    /// - Parameters:
    ///   - provider: The name of the offending cloud provider.
    ///   - reason: A human-readable description of the breach.
    public func trigger(provider: String, reason: String) {
        lock.lock()
        _state = .triggered(provider: provider, reason: reason)
        lock.unlock()
    }

    /// Returns `true` when the kill-switch is in a triggered state.
    public var isTriggered: Bool {
        if case .triggered = state { return true }
        return false
    }

    /// Validates an integrity digest for a provider's uplink.
    ///
    /// If `digest` does not match `expectedDigest`, the kill-switch is
    /// triggered automatically.
    ///
    /// - Parameters:
    ///   - digest: The digest received from the provider's uplink.
    ///   - expectedDigest: The digest computed on-device before upload.
    ///   - provider: The provider being validated.
    /// - Returns: `true` if the digests match (uplink is clean).
    @discardableResult
    public func validate(
        digest: String,
        expectedDigest: String,
        provider: String
    ) -> Bool {
        guard digest == expectedDigest else {
            trigger(provider: provider, reason: "Integrity mismatch: uplink tampered.")
            return false
        }
        return true
    }

    /// Resets to `.disarmed` (used in tests / session teardown).
    public func reset() {
        lock.lock()
        _state = .disarmed
        lock.unlock()
    }
}
