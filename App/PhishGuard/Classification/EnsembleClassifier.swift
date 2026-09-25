import Foundation
import OSLog
import PhishCore

/// What one model answered about one message.
///
/// Identifiers, scores, timings and short error text only — never mail content — so it is safe to keep in the
/// Diagnostics trace buffer and to log.
struct ModelRun: Sendable, Equatable {
    enum Outcome: Sendable, Equatable {
        /// The model answered.
        case answered(ModelAssessment)
        /// Not asked, and not the model's fault: it runs on the GPU and PhishGuard is not frontmost
        /// (`ForegroundGate`). Expected on every background scan with a downloaded model.
        case notFrontmost(String)
        /// Not asked: the model reported itself unavailable (Apple Intelligence off, model not downloaded,
        /// not enough free memory, …).
        case unavailable(String)
        /// Asked, and it declined this particular message (guardrails). Per message, never permanent.
        case declined(String)
        /// A real failure: load error, unparseable answer, anything unexpected.
        case failed(String)
        /// The scan's deadline or a cancellation stopped it.
        case interrupted
    }

    /// What this model was asked to be for this message. A single-model scan only ever has a primary.
    enum Role: String, Sendable, Equatable {
        /// Its answer is the ensemble's answer.
        case primary
        /// A second opinion. It may confirm what something else already found; it may never raise the alarm on
        /// its own. See `EnsembleClassifier` for why.
        case corroborator
    }

    /// What became of a corroborator's answer. Nil for the primary and for a member that never answered.
    enum Corroboration: String, Sendable, Equatable {
        /// It scored higher than the primary **and** something independent supported that, so its score decided.
        case adopted
        /// It scored higher than the primary and nothing supported it, so its score was discarded: the primary's
        /// assessment (or, with no primary answer, the rules alone) stands.
        case suppressed
        /// It answered without exceeding the primary — nothing to adopt, nothing to suppress.
        case notHigher
    }

    let identifier: String
    let outcome: Outcome
    /// Wall-clock time this model took (for an ensemble member, including its availability check).
    let duration: TimeInterval
    let role: Role
    let corroboration: Corroboration?

    init(
        identifier: String,
        outcome: Outcome,
        duration: TimeInterval,
        role: Role = .primary,
        corroboration: Corroboration? = nil
    ) {
        self.identifier = identifier
        self.outcome = outcome
        self.duration = duration
        self.role = role
        self.corroboration = corroboration
    }

    /// The same run with its corroboration outcome decided.
    func recording(_ corroboration: Corroboration) -> ModelRun {
        ModelRun(identifier: identifier, outcome: outcome, duration: duration, role: role, corroboration: corroboration)
    }

    var assessment: ModelAssessment? {
        if case .answered(let assessment) = outcome { return assessment }
        return nil
    }

    var riskScore: Int? { assessment?.riskScore }
    var category: ThreatCategory? { assessment?.category }

    /// Short description of why this model did not answer; nil when it did.
    var errorDescription: String? {
        switch outcome {
        case .answered: return nil
        case .notFrontmost(let reason), .unavailable(let reason), .declined(let reason), .failed(let reason): return reason
        case .interrupted: return "stopped (scan deadline or cancellation)"
        }
    }

    /// One line for the Diagnostics panel: why this model did not answer, or what its answer was used for.
    /// Never mail content. Nil when there is nothing to add beyond the score.
    var statusDescription: String? {
        if let errorDescription { return errorDescription }
        switch corroboration {
        case .adopted: return "corroborator, adopted"
        case .suppressed: return "corroborator, suppressed (nothing corroborated it)"
        case .notHigher: return "corroborator, did not raise"
        case nil: return nil
        }
    }

    /// True when this member answered with a higher score that was thrown away for want of independent support.
    var wasSuppressed: Bool { corroboration == .suppressed }

    /// True only for genuine failures — the ones the coordinator's consecutive-failure breaker counts.
    var didFail: Bool {
        if case .failed = outcome { return true }
        return false
    }

    /// True when the model was passed over because PhishGuard is not frontmost.
    var wasSkippedForForeground: Bool {
        if case .notFrontmost = outcome { return true }
        return false
    }

    var wasInterrupted: Bool {
        if case .interrupted = outcome { return true }
        return false
    }
}

/// The combined answer of one or more models for one message.
struct MultiModelAssessment: Sendable {
    /// What the ensemble concluded: the primary's assessment, or a corroborator's higher one where independent
    /// support allowed it to be adopted. Nil when nothing usable was produced, which the caller turns into a
    /// rules-only verdict.
    var assessment: ModelAssessment?
    /// What to record as `Verdict.modelIdentifier`: the member's own identifier when exactly one answered and
    /// nothing was suppressed, `ensemble(a,b)→winner` when several did, `…→winner⊘c` when `c`'s higher score was
    /// suppressed, nil when nothing was adopted.
    var modelIdentifier: String?
    /// One entry per member that was considered, in member order.
    var runs: [ModelRun]
    /// True when a GPU-backed member was passed over because PhishGuard is not frontmost.
    var foregroundSkipped: Bool

    init(assessment: ModelAssessment? = nil, modelIdentifier: String? = nil, runs: [ModelRun] = [], foregroundSkipped: Bool = false) {
        self.assessment = assessment
        self.modelIdentifier = modelIdentifier
        self.runs = runs
        self.foregroundSkipped = foregroundSkipped
    }

    /// True when at least one member failed for an unexpected reason (an unavailable or declining model is not
    /// a failure, so it must never trip the coordinator's breaker).
    var hasFailure: Bool { runs.contains { $0.didFail } }

    /// True when a corroborator's higher score was discarded for want of independent support.
    var hasSuppressedCorroborator: Bool { runs.contains { $0.wasSuppressed } }

    /// Why nothing was adopted, for the "model unavailable for this message" error and the log.
    var failureReason: String {
        var reasons = runs.compactMap(\.errorDescription)
        if hasSuppressedCorroborator {
            reasons.append("A second model flagged this message but nothing corroborated it.")
        }
        return reasons.isEmpty ? "No detection model answered." : reasons.joined(separator: " ")
    }
}

/// A classifier that consults more than one model for the same message and reports what each one said.
///
/// `ScanCoordinator` recognises this and uses `assessAll` instead of `assess`, so one model being unavailable
/// never silences the other and the per-model answers reach the Diagnostics trace.
protocol MultiModelClassifier: EmailClassifier {
    func assessAll(_ input: ClassificationInput) async -> MultiModelAssessment
}

/// The `Verdict.modelIdentifier` an ensemble writes: which models were consulted, whose score decided, and
/// whose higher score was thrown away for want of corroboration.
///
/// `"ensemble(mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit,apple.foundation)→mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit"`
/// — and with the second opinion suppressed, the same string plus `"⊘apple.foundation"`. The classifier's own
/// `identifier` uses the shape without the arrow (nothing has run yet). Members are listed primary first.
enum EnsembleIdentifier {
    static let prefix = "ensemble("
    static let arrow = "→"
    /// Marks the corroborators whose higher score was **not** adopted, so a verdict that looks quiet next to a
    /// loud second opinion explains itself in the detail screen and the debug panel.
    static let suppressed = "⊘"

    static func make(members: [String], winner: String?, suppressed suppressedMembers: [String] = []) -> String {
        var out = prefix + members.joined(separator: ",") + ")"
        if let winner { out += arrow + winner }
        if !suppressedMembers.isEmpty { out += suppressed + suppressedMembers.joined(separator: ",") }
        return out
    }

    /// Splits an identifier written by `make`; nil for every other identifier.
    static func parse(_ identifier: String) -> (members: [String], winner: String?, suppressed: [String])? {
        guard identifier.hasPrefix(prefix), let close = identifier.lastIndex(of: ")") else { return nil }
        let start = identifier.index(identifier.startIndex, offsetBy: prefix.count)
        guard start <= close else { return nil }
        let members = list(identifier[start..<close])
        var rest = identifier[identifier.index(after: close)...]
        var suppressedMembers: [String] = []
        if let mark = rest.range(of: suppressed) {
            suppressedMembers = list(rest[mark.upperBound...])
            rest = rest[..<mark.lowerBound]
        }
        guard rest.hasPrefix(arrow) else { return (members, nil, suppressedMembers) }
        let winner = String(rest.dropFirst(arrow.count))
        return (members, winner.isEmpty ? nil : winner, suppressedMembers)
    }

    private static func list(_ text: Substring) -> [String] {
        text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

/// Runs a **primary** model and one or more **corroborators** on the same email concurrently, and lets a
/// corroborator confirm the primary without ever letting it raise the alarm by itself.
///
/// ### Why this is not "take the highest of both models"
///
/// It was, briefly. `Tools/PromptLab` then measured the two real models on one Mac over 37 emails (the 29
/// shipped `SampleEmails` fixtures plus the 8 adversarial probes), and the maximum turned out to be the wrong
/// combination for *these two* detectors:
///
/// - **MLX (Qwen3-4B)** caught 12/12 malicious on the shipped corpus with 0/17 benign false positives. It is a
///   good primary.
/// - **Apple FoundationModels** caught 17/17 malicious but scored 10 of 19 benign messages at 75–90 — a bank
///   statement, a Google security alert, a Zoom invite, a Docs share, a one-time code, an internal HR notice, a
///   Shopify order, a retail promo and two probes. Worse, its stated reasons were largely verbatim echoes of the
///   heuristic findings rendered into the prompt, so a high Apple score is mostly *the rules again*, not a second
///   opinion.
/// - Under a maximum, running both would therefore have turned **7 of 20 benign messages into real alerts**;
///   only `VerdictEngine`'s authenticated-brand cap rescued four of them.
///
/// A maximum is the right rule between the rules and a model, because those two read different evidence. It is
/// the wrong rule between two models that read the *same* rendered prompt: the noisier one simply wins every
/// disagreement, and the ensemble inherits its false positives instead of the better model's precision.
///
/// ### The rule
///
/// One member is the primary; the rest are corroborators.
///
/// - A corroborator's **higher** `riskScore` is adopted only when there is **independent support** — the primary
///   answered with `primarySupportScore` (40) or more, **or** the rule engine scored this email at
///   `heuristicSupportScore` (0.3) or more. Something other than the second model has to have noticed
///   *something*.
/// - Without support the corroborator cannot raise the result at all: the primary's assessment stands, or — when
///   no primary answered — the caller gets no assessment and falls back to the rules alone.
/// - A corroborator may never *lower* anything: it is only ever consulted about raising.
/// - Which member is the primary is fixed by the user's choice, never by who happens to be able to run. With
///   "Both models" the downloaded MLX model is the primary and Apple Intelligence corroborates, and when MLX
///   cannot run — background scan behind the `ForegroundGate`, or nothing downloaded — Apple stays a
///   corroborator. It must not be promoted, because background scans are exactly where it would otherwise run
///   alone and produce the false alerts above. Picking Apple Intelligence on its own in Settings makes it the
///   primary, which is the user saying so explicitly.
///
/// Every member's answer is recorded in its own `ModelRun` — including a corroborator's score and whether it was
/// adopted or suppressed — so the Diagnostics panel shows what was consulted and why the verdict is what it is.
///
/// ### What it measures now
///
/// Re-measured over the full 38-email corpus (30 fixtures + 8 probes), fused verdict, `AlertPolicy()` at
/// `.medium`: rules only 15/17 malicious and 0/21 benign; MLX alone 17/17 and 1/21; Apple alone 17/17 and
/// **7/21**; this ensemble 17/17 and 1/21 — equal to the better model, with Apple's score adopted on 2 malicious
/// messages and suppressed on 13 benign ones it had scored 75–100. With the primary gated off (a background
/// scan) it is 17/17 and **0/21**, against 7/21 for Apple running alone there. The remaining benign alert is the
/// lab probe `probeBenignStrangerRestoreDoc`, which is MLX's own error and is inherited from the primary; no
/// shipped `SampleEmails` fixture alerts. Full tables in `Tools/PromptLab/README.md`.
///
/// **Foreground.** A `GPUBackedClassifier` member is skipped outright while PhishGuard is not frontmost: iOS
/// terminates an app that submits Metal work from the background (`ForegroundGate`). Apple's `FoundationModels`
/// member is a system service and is unaffected.
///
/// **Cancellation.** The members run in one task group, so cancelling the caller (the scan deadline, a BGTask
/// expiring) cancels every member.
struct EnsembleClassifier: MultiModelClassifier {
    /// Whose answer the ensemble reports.
    let primary: any EmailClassifier
    /// Second opinions: they may confirm the primary, never outvote the rest of the evidence on their own.
    let corroborators: [any EmailClassifier]
    /// "May we use the GPU right now?" — read before a GPU-backed member is even asked for its availability.
    private let foregroundGate: any ForegroundGate

    /// `riskScore` from which the primary's own answer counts as independent support for a louder corroborator.
    /// Below it the primary has not found anything for the second model to confirm.
    static let primarySupportScore = 40

    /// Heuristic score (`ClassificationInput.report.score`) from which the rule engine counts as independent
    /// support on its own. Deliberately the `.low` verdict threshold: the rules need only have *noticed*
    /// something, not alerted. This is what lets a corroborator still matter on a background scan, where the
    /// primary cannot run at all.
    static let heuristicSupportScore = 0.3

    private static let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "ensemble")

    init(primary: any EmailClassifier, corroborators: [any EmailClassifier], foregroundGate: any ForegroundGate = AppForegroundGate.shared) {
        self.primary = primary
        self.corroborators = corroborators
        self.foregroundGate = foregroundGate
    }

    /// Every member consulted, primary first — the order the identifier and the Diagnostics rows use.
    var members: [any EmailClassifier] { [primary] + corroborators }

    var identifier: String { EnsembleIdentifier.make(members: members.map(\.identifier), winner: nil) }

    var displayName: String { "Both models" }

    // MARK: - EmailClassifier

    /// Available as soon as one member is — a corroborator alone can still confirm a heuristic finding, which is
    /// the background case. The reasons of the unavailable members are joined otherwise, so the Model screen can
    /// say why "Both models" cannot run on this device right now.
    func availability() async -> ClassifierAvailability {
        let members = self.members
        let isForeground = foregroundGate.isForeground
        var reasons: [String] = []
        for member in members {
            if member is any GPUBackedClassifier, !isForeground {
                reasons.append(MLXClassifier.foregroundOnlyReason)
                continue
            }
            switch await member.availability() {
            case .available:
                return .available
            case .unavailable(let reason):
                reasons.append(reason)
            }
        }
        return .unavailable(reason: reasons.joined(separator: " "))
    }

    /// The adopted assessment. Throws when there is none — including when the only answer was an uncorroborated
    /// second opinion — so a caller that only knows `EmailClassifier` falls back to the rules exactly as it does
    /// for a single model.
    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        let result = await assessAll(input)
        if let assessment = result.assessment { return assessment }
        if result.runs.contains(where: \.wasInterrupted) { throw CancellationError() }
        throw ClassifierError.unavailable(result.failureReason)
    }

    // MARK: - MultiModelClassifier

    func assessAll(_ input: ClassificationInput) async -> MultiModelAssessment {
        let members = self.members
        let isForeground = foregroundGate.isForeground
        var runs: [Int: ModelRun] = [:]
        var candidates: [(index: Int, member: any EmailClassifier)] = []
        for (index, member) in members.enumerated() {
            let role: ModelRun.Role = index == 0 ? .primary : .corroborator
            // Checked here rather than left to the member: nothing may reach a GPU-backed classifier while the
            // gate is closed, and the fallback has to be recorded as "expected", not as a model failure.
            if member is any GPUBackedClassifier, !isForeground {
                runs[index] = ModelRun(
                    identifier: member.identifier,
                    outcome: .notFrontmost(MLXClassifier.foregroundOnlyReason),
                    duration: 0,
                    role: role
                )
                continue
            }
            candidates.append((index, member))
        }

        if !candidates.isEmpty {
            let collected = await withTaskGroup(of: (Int, ModelRun).self, returning: [(Int, ModelRun)].self) { group in
                for candidate in candidates {
                    let role: ModelRun.Role = candidate.index == 0 ? .primary : .corroborator
                    group.addTask { (candidate.index, await Self.run(candidate.member, as: role, on: input)) }
                }
                var results: [(Int, ModelRun)] = []
                for await result in group { results.append(result) }
                return results
            }
            for (index, run) in collected { runs[index] = run }
        }

        return Self.combine(members.indices.compactMap { runs[$0] }, heuristicScore: input.report.score)
    }

    // MARK: - Helpers (static so they can be tested without a device)

    /// Availability check plus one assessment, with every failure mode mapped to an outcome instead of an error:
    /// one member must never be able to abort the others.
    private static func run(_ member: any EmailClassifier, as role: ModelRun.Role, on input: ClassificationInput) async -> ModelRun {
        let startedAt = Date()
        func finish(_ outcome: ModelRun.Outcome) -> ModelRun {
            ModelRun(identifier: member.identifier, outcome: outcome, duration: Date().timeIntervalSince(startedAt), role: role)
        }

        if case .unavailable(let reason) = await member.availability() {
            return finish(.unavailable(reason))
        }
        do {
            return finish(.answered(try await member.assess(input)))
        } catch is CancellationError {
            return finish(.interrupted)
        } catch ClassifierError.requiresForeground(let reason) {
            return finish(.notFrontmost(reason))
        } catch ClassifierError.guardrailViolation {
            return finish(.declined(ClassifierError.guardrailViolation.errorDescription ?? "The model declined this message."))
        } catch ClassifierError.noModel {
            return finish(.unavailable("No model is configured."))
        } catch ClassifierError.unavailable(let reason) {
            return finish(.unavailable(reason))
        } catch {
            logger.notice("Ensemble member \(member.identifier, privacy: .public) failed: \(error.localizedDescription, privacy: .private)")
            return finish(.failed(error.localizedDescription))
        }
    }

    /// True when something other than the corroborator itself found this message worth a second look: the
    /// primary answered at `primarySupportScore` or more, or the rule engine scored it at
    /// `heuristicSupportScore` or more.
    static func hasIndependentSupport(primaryRiskScore: Int?, heuristicScore: Double) -> Bool {
        if let primaryRiskScore, primaryRiskScore >= primarySupportScore { return true }
        return heuristicScore >= heuristicSupportScore
    }

    /// Applies the corroboration rule to the members' answers and annotates each run with what became of it.
    ///
    /// Deterministic although the members ran concurrently: the runs arrive in member order, the primary decides
    /// the baseline, and each corroborator is then considered in turn against whatever has been adopted so far.
    static func combine(_ runs: [ModelRun], heuristicScore: Double) -> MultiModelAssessment {
        let foregroundSkipped = runs.contains { $0.wasSkippedForForeground }
        let primaryRun = runs.first { $0.role == .primary && $0.assessment != nil }
        let support = hasIndependentSupport(primaryRiskScore: primaryRun?.riskScore, heuristicScore: heuristicScore)

        var winner = primaryRun
        var annotated: [ModelRun] = []
        var suppressedMembers: [String] = []
        var answered: [String] = []
        for run in runs {
            guard run.assessment != nil else { annotated.append(run); continue }
            answered.append(run.identifier)
            guard run.role == .corroborator else { annotated.append(run); continue }
            if (run.riskScore ?? 0) > (winner?.riskScore ?? Int.min) {
                if support {
                    let adopted = run.recording(.adopted)
                    winner = adopted
                    annotated.append(adopted)
                } else {
                    // The only brake that matters: a loud second opinion nothing else agrees with is dropped.
                    suppressedMembers.append(run.identifier)
                    annotated.append(run.recording(.suppressed))
                }
            } else {
                annotated.append(run.recording(.notHigher))
            }
        }

        guard let winner else {
            return MultiModelAssessment(runs: annotated, foregroundSkipped: foregroundSkipped)
        }
        let identifier = answered.count == 1 && suppressedMembers.isEmpty
            ? winner.identifier
            : EnsembleIdentifier.make(members: answered, winner: winner.identifier, suppressed: suppressedMembers)
        return MultiModelAssessment(
            assessment: winner.assessment,
            modelIdentifier: identifier,
            runs: annotated,
            foregroundSkipped: foregroundSkipped
        )
    }
}
