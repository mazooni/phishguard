import Foundation

/// Decides whether a verdict is worth a notification. Never alerts for `.safe`.
public struct AlertPolicy: Sendable, Codable, Equatable {
    public var minimumLevel: RiskLevel

    public init(minimumLevel: RiskLevel = .medium) {
        self.minimumLevel = minimumLevel
    }

    public func shouldAlert(_ verdict: Verdict) -> Bool {
        verdict.level != .safe && verdict.level >= minimumLevel
    }
}
