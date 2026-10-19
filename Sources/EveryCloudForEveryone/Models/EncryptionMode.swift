/// The encryption mode applied when sealing a cloud account or file.
public enum EncryptionMode: String, Sendable {
    /// Full Signal Protocol (Double-Ratchet + X3DH).
    case signalFull = "SIGNAL_FULL"
    /// Hybrid PGP + Signal session keys.
    case pgpSignalHybrid = "PGP_SIGNAL_HYBRID"
    /// PGP for email/web contexts.
    case pgpWeb = "PGP_WEB"
    /// Signal + PGP combined (notes / documents).
    case signalPGP = "SIGNAL_PGP"
}

/// Outcome of a seal or enforcement operation.
public enum EnforcementResult: Equatable, Sendable {
    case success(provider: String)
    case failure(provider: String, reason: String)

    public var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}
