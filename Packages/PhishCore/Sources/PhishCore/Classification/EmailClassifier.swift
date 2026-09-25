import Foundation

/// A local (on-device) classifier. Implementations: Apple Foundation Models, MLX, heuristics-only.
public protocol EmailClassifier: Sendable {
    /// "apple.foundation", "mlx:<repo>", "heuristics"
    var identifier: String { get }
    var displayName: String { get }
    func availability() async -> ClassifierAvailability
    func assess(_ input: ClassificationInput) async throws -> ModelAssessment
}
