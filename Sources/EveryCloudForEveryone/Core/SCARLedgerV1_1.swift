import Foundation
import Crypto

public struct SCARV1_1Event: Codable, Sendable, Equatable {
    public let sequence: Int
    public let eventType: String
    public let timestamp: String
    public let provider: String
    public let reason: String
    public let action: String
    public let previousEventHash: String
    public let eventHash: String

    public enum CodingKeys: String, CodingKey {
        case sequence
        case eventType = "event_type"
        case timestamp
        case provider
        case reason
        case action
        case previousEventHash = "previous_event_hash"
        case eventHash = "event_hash"
    }
}

public final class SCARLedgerV1_1: @unchecked Sendable {
    private var events: [SCARV1_1Event] = []
    private let lock = NSLock()

    public init() {}

    public var snapshot: [SCARV1_1Event] {
        lock.lock()
        defer { lock.unlock() }
        return events
    }

    @discardableResult
    public func append(
        eventType: String,
        provider: String,
        reason: String,
        action: String,
        timestamp: String = SCARLedgerV1_1.utcTimestamp()
    ) throws -> SCARV1_1Event {
        lock.lock()
        defer { lock.unlock() }

        let sequence = events.count + 1
        let previous = events.last?.eventHash ?? String(repeating: "0", count: 64)
        let unsigned = UnsignedEvent(
            sequence: sequence,
            eventType: eventType,
            timestamp: timestamp,
            provider: provider,
            reason: reason,
            action: action,
            previousEventHash: previous
        )

        let hash = try Self.sha256Hex(Self.canonicalJSON(unsigned))
        let event = SCARV1_1Event(
            sequence: sequence,
            eventType: eventType,
            timestamp: timestamp,
            provider: provider,
            reason: reason,
            action: action,
            previousEventHash: previous,
            eventHash: hash
        )

        events.append(event)
        return event
    }

    private struct UnsignedEvent: Codable {
        let sequence: Int
        let eventType: String
        let timestamp: String
        let provider: String
        let reason: String
        let action: String
        let previousEventHash: String

        enum CodingKeys: String, CodingKey {
            case sequence
            case eventType = "event_type"
            case timestamp
            case provider
            case reason
            case action
            case previousEventHash = "previous_event_hash"
        }
    }

    static func canonicalJSON<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    static func sha256Hex(_ data: Data) throws -> String {
        SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    @usableFromInline
    static func utcTimestamp() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}
