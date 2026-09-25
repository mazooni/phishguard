import Foundation
import OSLog
import PhishCore
#if canImport(FoundationModels)
import FoundationModels
#endif

/// iOS 26 Foundation Models classifier (`SystemLanguageModel.default`, guided generation into `PhishingAssessment`).
///
/// Every email gets a fresh single-turn `LanguageModelSession` (no transcript growth, no cross-email leakage). The
/// prompt is fitted to `model.contextSize` with ~700 tokens of headroom; if the model still reports a context
/// overflow the body is halved once — but only when that actually shortens the rendered prompt, since an identical
/// retry can only overflow again. Guardrail violations and refusals are retried once through the documented
/// `permissiveContentTransformations` guardrails with a plain JSON string response (parsed by `ModelOutputParser`),
/// unless the user turned that off (`SettingsStore.allowPermissiveGuardrails`). Everything else maps to
/// `ClassifierError`, which the coordinator treats as "no model for this message".
struct AppleFoundationClassifier: EmailClassifier {
    static let classifierIdentifier = "apple.foundation"
    /// Tokens kept free for the guided-generation schema, framework overhead and the answer.
    static let headroomTokens = PromptFitting.defaultHeadroomTokens
    /// Phrases the on-device model uses when it declines instead of answering (checked on the permissive path).
    static let refusalMarkers = [
        "sorry, i can't", "sorry, i cannot", "sorry, but i can't", "i can't help", "i cannot help", "i can’t help",
        "i'm unable to help", "i am unable to help", "can't assist", "cannot assist", "unable to assist",
        "i can't provide", "i cannot provide", "not able to help",
    ]

    let identifier = AppleFoundationClassifier.classifierIdentifier
    let displayName = "Apple Intelligence (on-device)"
    /// Retry guardrail failures once with permissive (string-only) guardrails.
    let allowPermissiveGuardrails: Bool

    private static let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "apple-foundation")

    init(allowPermissiveGuardrails: Bool = true) {
        self.allowPermissiveGuardrails = allowPermissiveGuardrails
    }

    // MARK: - EmailClassifier

    func availability() async -> ClassifierAvailability {
        #if canImport(FoundationModels)
        return Self.availability(of: SystemLanguageModel.default.availability)
        #else
        return .unavailable(reason: "The FoundationModels framework is not available in this build.")
        #endif
    }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        #if canImport(FoundationModels)
        let model = SystemLanguageModel.default
        if case .unavailable(let reason) = Self.availability(of: model.availability) {
            throw ClassifierError.unavailable(reason)
        }
        guard model.supportsLocale(.current) else {
            throw ClassifierError.unavailable("Apple Intelligence does not support the current language.")
        }

        let options = Self.greedyOptions
        var bodyCharacters = PromptFitting.fittedBodyCharacters(
            for: input, contextSize: model.contextSize, headroomTokens: Self.headroomTokens
        )
        var attempt = 0
        while true {
            attempt += 1
            do {
                return try await Self.guidedAssessment(input, bodyCharacters: bodyCharacters, model: model, options: options)
            } catch {
                if error is CancellationError { throw error }
                switch Self.stepFailure(for: error) {
                case .contextExceeded(let detail):
                    Self.logger.notice("Context window exceeded (attempt \(attempt), body \(bodyCharacters) chars): \(detail, privacy: .private)")
                    guard attempt == 1,
                          let shorter = Self.retryBodyCharacters(
                              after: bodyCharacters, bodyLength: input.report.bodyText.count
                          )
                    else {
                        throw ClassifierError.unavailable("The email is too long for the on-device model.")
                    }
                    bodyCharacters = shorter
                case .guardrail(let detail):
                    Self.logger.notice("Guardrail triggered by guided generation: \(detail, privacy: .private)")
                    guard allowPermissiveGuardrails else { throw ClassifierError.guardrailViolation }
                    return try await Self.permissiveAssessment(input, bodyCharacters: bodyCharacters, options: options)
                case .failed(let classifierError, let detail):
                    Self.logger.notice("Foundation model failed: \(detail, privacy: .private)")
                    throw classifierError
                }
            }
        }
        #else
        throw ClassifierError.unavailable("The FoundationModels framework is not available in this build.")
        #endif
    }

    // MARK: - Helpers shared with tests

    /// The body limit to retry an overflowing prompt with, or nil when the retry would send the identical prompt.
    ///
    /// `PromptBuilder.userPrompt` renders `bodyText.prefix(limit)`, so halving only helps when the rendered body
    /// actually gets shorter: not when the limit is already at `PromptFitting.minimumBodyCharacters`, and not when
    /// the body is shorter than the halved limit. Resending the same prompt to a fresh session cannot succeed — the
    /// context check is deterministic — and would only cost another request against the on-device rate limit.
    static func retryBodyCharacters(after bodyCharacters: Int, bodyLength: Int) -> Int? {
        let shrunk = max(PromptFitting.minimumBodyCharacters, bodyCharacters / 2)
        let renderedCharacters = min(bodyCharacters, bodyLength)
        return shrunk < renderedCharacters ? shrunk : nil
    }

    /// True when a plain-text answer is the model declining rather than the requested JSON.
    static func looksLikeRefusal(_ text: String) -> Bool {
        let normalized = text.lowercased().replacingOccurrences(of: "’", with: "'")
        guard !normalized.contains("{") else { return false }
        return refusalMarkers.contains { normalized.contains($0) }
    }

    #if canImport(FoundationModels)
    static func availability(of availability: SystemLanguageModel.Availability) -> ClassifierAvailability {
        switch availability {
        case .available:
            return .available
        case .unavailable(let reason):
            return .unavailable(reason: describe(reason))
        }
    }

    /// Human-readable text for the UI; covers every documented reason plus future ones.
    static func describe(_ reason: SystemLanguageModel.Availability.UnavailableReason) -> String {
        switch reason {
        case .deviceNotEligible:
            return "This device does not support Apple Intelligence."
        case .appleIntelligenceNotEnabled:
            return "Apple Intelligence is turned off. Enable it in Settings › Apple Intelligence & Siri."
        case .modelNotReady:
            return "The on-device model is still downloading or being prepared; try again later."
        @unknown default:
            return "Apple Intelligence is unavailable right now (\(String(describing: reason)))."
        }
    }

    // MARK: - Generation

    private enum StepFailure {
        case contextExceeded(String)
        case guardrail(String)
        case failed(ClassifierError, String)
    }

    /// Deterministic decoding. The `samplingMode:` spelling exists only in the iOS 27 SDK (Swift 6.4 toolchain),
    /// where `sampling:` is deprecated and would fail the warnings-as-errors build.
    private static var greedyOptions: GenerationOptions {
        #if compiler(>=6.4)
        return GenerationOptions(samplingMode: .greedy)
        #else
        return GenerationOptions(sampling: .greedy)
        #endif
    }

    private static func guidedAssessment(
        _ input: ClassificationInput,
        bodyCharacters: Int,
        model: SystemLanguageModel,
        options: GenerationOptions
    ) async throws -> ModelAssessment {
        // Trusted instructions only; the email is untrusted data and lives in the prompt (PromptBuilder wraps it).
        let session = LanguageModelSession(model: model, instructions: PromptBuilder.systemPrompt)
        let prompt = PromptBuilder.userPrompt(for: input, maxBodyCharacters: bodyCharacters)
        let response = try await session.respond(
            to: prompt,
            generating: PhishingAssessment.self,
            includeSchemaInPrompt: true,
            options: options
        )
        return response.content.modelAssessment
    }

    /// Secondary path: string-only response under permissive guardrails, parsed like the MLX output.
    private static func permissiveAssessment(
        _ input: ClassificationInput,
        bodyCharacters: Int,
        options: GenerationOptions
    ) async throws -> ModelAssessment {
        let model = SystemLanguageModel(guardrails: .permissiveContentTransformations)
        if case .unavailable(let reason) = availability(of: model.availability) {
            throw ClassifierError.unavailable(reason)
        }
        let session = LanguageModelSession(model: model, instructions: PromptBuilder.systemPrompt)
        let prompt = PromptBuilder.userPrompt(for: input, maxBodyCharacters: bodyCharacters)
            + "\n\n" + PromptBuilder.jsonOutputInstructions

        let text: String
        do {
            text = try await session.respond(to: prompt, options: options).content
        } catch {
            if error is CancellationError { throw error }
            switch stepFailure(for: error) {
            case .guardrail(let detail):
                logger.notice("Guardrail triggered again on the permissive path: \(detail, privacy: .private)")
                throw ClassifierError.guardrailViolation
            case .contextExceeded:
                throw ClassifierError.unavailable("The email is too long for the on-device model.")
            case .failed(let classifierError, let detail):
                logger.notice("Permissive path failed: \(detail, privacy: .private)")
                throw classifierError
            }
        }

        if looksLikeRefusal(text) {
            logger.notice("Permissive path returned a refusal")
            throw ClassifierError.guardrailViolation
        }
        do {
            return try ModelOutputParser.parseAssessment(from: text)
        } catch {
            logger.notice("Permissive path output was not parseable: \(String(describing: error), privacy: .private)")
            throw ClassifierError.invalidOutput(String(describing: error))
        }
    }

    /// Maps the iOS 26 `GenerationError` family. The iOS 27 SDK splits errors into new types that this SDK does not
    /// declare, so anything unknown (including those) falls into the catch-all as "unavailable for this message".
    private static func stepFailure(for error: any Error) -> StepFailure {
        if let generationError = error as? LanguageModelSession.GenerationError {
            switch generationError {
            case .guardrailViolation(let context):
                return .guardrail(context.debugDescription)
            case .refusal(_, let context):
                return .guardrail(context.debugDescription)
            case .exceededContextWindowSize(let context):
                return .contextExceeded(context.debugDescription)
            case .rateLimited(let context):
                return .failed(.unavailable("rate limited"), context.debugDescription)
            case .unsupportedLanguageOrLocale(let context):
                return .failed(.unavailable("Apple Intelligence does not support the language of this email."), context.debugDescription)
            case .decodingFailure(let context):
                return .failed(.invalidOutput("The model's structured answer could not be decoded."), context.debugDescription)
            case .assetsUnavailable(let context):
                return .failed(.unavailable("The on-device model assets are unavailable right now."), context.debugDescription)
            case .concurrentRequests(let context):
                return .failed(.unavailable("The on-device model is busy with another request."), context.debugDescription)
            case .unsupportedGuide(let context):
                return .failed(.invalidOutput("The generation schema is not supported by this model version."), context.debugDescription)
            @unknown default:
                return .failed(.unavailable("Apple Intelligence error: \(generationError.localizedDescription)"), String(describing: generationError))
            }
        }
        return .failed(.unavailable("Apple Intelligence error: \(error.localizedDescription)"), String(describing: error))
    }
    #endif
}
