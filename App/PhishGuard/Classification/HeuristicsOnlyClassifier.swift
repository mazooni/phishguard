import Foundation
import PhishCore

/// No model at all. `assess` throws `ClassifierError.noModel`; the coordinator recognises the identifier and passes
/// `assessment: nil` to the `VerdictEngine` without calling `assess`.
struct HeuristicsOnlyClassifier: EmailClassifier {
    static let classifierIdentifier = "heuristics"

    let identifier = HeuristicsOnlyClassifier.classifierIdentifier
    let displayName = "Heuristics only (no model)"

    init() {}

    func availability() async -> ClassifierAvailability {
        .available
    }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        throw ClassifierError.noModel
    }
}
