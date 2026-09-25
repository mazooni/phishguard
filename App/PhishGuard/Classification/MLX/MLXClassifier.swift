import Foundation
import OSLog
import PhishCore
import Synchronization
#if !targetEnvironment(simulator)
import HuggingFace
import MLX
import MLXLLM
import MLXLMCommon
#endif

/// Local LLM classifier backed by mlx-swift-lm and a model downloaded by `ModelManager`.
///
/// One instance per model id (owned by `ClassifierRegistry`). Classifications are single-flight: the actor serialises
/// `assess` calls, loads the `ModelContainer` once and keeps it resident so every message of a scan reuses it,
/// generates greedily (temperature 0, ≤ 300 tokens) and parses the JSON with `ModelOutputParser`. Multi-GB weights
/// are dropped only by `releaseResources()` — which `ScanCoordinator` calls at the end of every scan and on a memory
/// warning — or by `setKeepLoaded(false)`, which unloads and restores unload-after-every-classification for callers
/// that classify a single message. Not available on the iOS Simulator (MLX needs a real GPU).
///
/// **Foreground only.** Every forward pass runs on the GPU and each generated token submits new Metal command
/// buffers. iOS refuses that from an app that is not frontmost and reports the refusal as an uncaught C++
/// exception (`[METAL] … Insufficient Permission (to submit GPU work from background)`), which kills the process
/// and cannot be caught in Swift. So this classifier asks `ForegroundGate` before it does anything: `availability()`
/// reports itself unavailable and `assess(_:)` throws `ClassifierError.requiresForeground` immediately — before any
/// weight is loaded — whenever the gate is closed, and an in-flight generation is cancelled the moment the gate
/// closes (see `generate(container:prompt:)`).
actor MLXClassifier: GPUBackedClassifier {
    static let maxTokens = 300
    static let maxBodyCharacters = 2_500
    /// Bounds KV-cache growth (research §6): prompts are ≤ ~1.5k tokens, so 4k is generous.
    static let maxKVSize = 4_096
    /// MLX iOS guidance: keep the Metal buffer cache tiny so jetsam limits are not hit.
    static let cacheLimitBytes = 20 * 1024 * 1024
    /// What the user is told when the local model is asked to run while PhishGuard is not frontmost. Shown by the
    /// Model settings screen and recorded in the scan log; deliberately free of GPU/Metal jargon.
    static let foregroundOnlyReason = "The downloaded model only runs while PhishGuard is open; background checks use the built-in rules."

    nonisolated let modelID: String
    nonisolated let entry: ModelManager.CatalogEntry?

    #if !targetEnvironment(simulator)
    private let cache: HubCache
    private let downloader: HubDownloader
    private var container: ModelContainer?
    private var loadTask: Task<ModelContainer, any Error>?
    #endif
    /// Keeps the weights resident between classifications so a scan pays one load, not one per message
    /// (`ScanCoordinator` releases them again at the end of every scan and on memory warnings).
    private var keepLoaded = true
    private var isBusy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "mlx")
    /// Read before every load and before every generation; never blocks, never hops to the main actor.
    private nonisolated let foregroundGate: any ForegroundGate
    /// Lock-protected handle on the generation currently on the GPU, so the gate's observer can cancel it from the
    /// main thread without waiting for this actor (which is busy awaiting that very generation).
    private nonisolated let generationHandle = GenerationHandle()
    /// Kept alive for the classifier's lifetime; dropping it would unsubscribe.
    private nonisolated let foregroundSubscription: ForegroundGateSubscription

    init(modelID: String, modelManager: ModelManager, foregroundGate: any ForegroundGate = AppForegroundGate.shared) {
        self.modelID = modelID
        self.entry = ModelManager.entry(for: modelID)
        self.foregroundGate = foregroundGate
        #if !targetEnvironment(simulator)
        self.cache = modelManager.cache
        self.downloader = HubDownloader(hub: modelManager.hub, localFilesOnly: true)
        #endif
        let handle = generationHandle
        // Synchronous on the thread that flipped the state (the main thread for `willResignActive`), so the token
        // loop stops at its next token boundary instead of submitting another command buffer.
        self.foregroundSubscription = foregroundGate.onForegroundChange { isForeground in
            if !isForeground { handle.cancel() }
        }
    }

    nonisolated var identifier: String { "mlx:\(entry?.hfRepo ?? modelID)" }

    nonisolated var displayName: String { "Local model (\(entry?.displayName ?? modelID))" }

    // MARK: - EmailClassifier

    func availability() async -> ClassifierAvailability {
        // Checked before the simulator branch so the answer is the same on every platform: no foreground, no GPU.
        guard foregroundGate.isForeground else {
            return .unavailable(reason: Self.foregroundOnlyReason)
        }
        #if targetEnvironment(simulator)
        return .unavailable(reason: "Local MLX models cannot run on the simulator; use a physical iPhone.")
        #else
        guard let entry else {
            return .unavailable(reason: "Unknown model \"\(modelID)\".")
        }
        guard ModelManager.isDownloaded(repo: entry.hfRepo, in: cache) else {
            return .unavailable(reason: "\(entry.displayName) has not been downloaded. Download it in Settings › Detection model.")
        }
        if container == nil, let available = DeviceMemory.availableMemoryBytes(), available < entry.estimatedRuntimeBytes {
            return .unavailable(
                reason: "Not enough free memory to run \(entry.displayName) right now "
                    + "(needs about \(DeviceMemory.formatted(entry.estimatedRuntimeBytes)), "
                    + "\(DeviceMemory.formatted(available)) available)."
            )
        }
        return .available
        #endif
    }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        // First statement of the method on purpose: nothing below it may run without a frontmost app, not even
        // loading weights from disk (which would only be followed by a forbidden command-buffer submission).
        try checkForeground()
        #if targetEnvironment(simulator)
        throw ClassifierError.unavailable("Local MLX models cannot run on the simulator.")
        #else
        guard let entry else { throw ClassifierError.unavailable("Unknown model \"\(modelID)\".") }
        await acquire()
        defer { release() }
        // Waiting behind another message can take seconds; the app may have left the foreground meanwhile.
        try checkForeground()

        let container = try await loadContainer(entry)
        defer { if !keepLoaded { unload() } }
        // mlx-swift-lm's loader has no cancellation points, so a scan cancelled during a multi-GB load only finds
        // out here. Stop before generating: `TokenIterator.init` prefills the whole prompt on the GPU before the
        // token loop's first `Task.isCancelled` check.
        try Task.checkCancellation()
        // The load reads gigabytes from flash; re-check rather than prefill a prompt we may no longer submit.
        try checkForeground()

        var prompt = PromptBuilder.userPrompt(for: input, maxBodyCharacters: Self.maxBodyCharacters)
        prompt += "\n\n" + PromptBuilder.jsonOutputInstructions
        if entry.isThinkingModel {
            // Qwen3 soft switch; `enable_thinking` is not forwarded to the chat template (mlx-swift-lm #154).
            prompt += "\n/no_think"
        }

        let text: String
        do {
            text = try await generate(container: container, prompt: prompt)
        } catch is CancellationError {
            // Either the caller cancelled us (scan deadline, BGTask expiry) or the foreground gate did.
            try checkForeground()
            throw CancellationError()
        } catch {
            logger.error("Generation failed for \(entry.hfRepo, privacy: .public): \(error.localizedDescription, privacy: .private)")
            throw ClassifierError.unavailable("Generation failed: \(error.localizedDescription)")
        }

        // `ChatSession.respond` does not throw on cancellation: mlx-swift-lm's token loop sets
        // `stopReason = .cancelled`, breaks, and the text accumulated so far is returned normally. A fragment
        // produced because the app stopped being frontmost is not a verdict and not a model failure either.
        try checkForeground()
        try Task.checkCancellation()

        let answer = Self.strippingThinkingBlocks(text)
        guard Self.hasClosedJSONObject(answer) else {
            logger.notice("Model output from \(entry.hfRepo, privacy: .public) was cut off before its JSON object closed")
            throw ClassifierError.invalidOutput("the model's answer was cut off before it finished")
        }
        do {
            return try ModelOutputParser.parseAssessment(from: answer)
        } catch {
            logger.notice("Unparseable model output from \(entry.hfRepo, privacy: .public): \(String(describing: error), privacy: .private)")
            throw ClassifierError.invalidOutput(String(describing: error))
        }
        #endif
    }

    // MARK: - Lifecycle

    /// Whether a loaded model survives the next classification. True unless a caller turned residency off.
    var keepsModelLoaded: Bool { keepLoaded }

    /// Whether the weights stay resident between classifications; on by default so the messages of one scan share a
    /// single load, with `releaseResources()` dropping them at the end of every scan and on memory warnings.
    /// Passing `false` unloads now and keeps unloading after every later classification until it is turned back on
    /// (for callers that classify one message and never reach a scan-end release).
    func setKeepLoaded(_ keep: Bool) {
        keepLoaded = keep
        if !keep { unload() }
    }

    /// Drops the model container and returns cached Metal buffers. Safe to call at any time (e.g. before the app
    /// suspends or on a memory warning); a classification in flight keeps its own reference until it finishes.
    ///
    /// On the way to the background the generation is cancelled *before* this runs: `AppEnvironment` closes the
    /// foreground gate (which cancels synchronously) and only then asks the registry to release.
    func releaseResources() {
        unload()
    }

    // MARK: - Helpers

    /// Throws `ClassifierError.requiresForeground` unless the app is frontmost. The coordinator treats that error
    /// as "expected, use the rules for this message" rather than as a classifier failure.
    private nonisolated func checkForeground() throws {
        guard foregroundGate.isForeground else {
            throw ClassifierError.requiresForeground(Self.foregroundOnlyReason)
        }
    }

    /// True when the first `{` in `text` is closed by its matching bracket (string- and escape-aware), i.e. the
    /// generation ran to the end of its JSON object.
    ///
    /// `ModelOutputParser` deliberately repairs unbalanced output: it closes open strings and brackets and keeps a
    /// trailing number that merely looks finished, so an answer cut off after `"riskScore": 9` (of an intended 92)
    /// would decode into a real, model-attributed verdict. A cut-off answer is not a verdict, so the MLX path
    /// refuses it instead. Text with no `{` at all is left to the parser, which reports `noJSONObjectFound`.
    nonisolated static func hasClosedJSONObject(_ text: String) -> Bool {
        guard let open = text.firstIndex(of: "{") else { return true }
        var depth = 0
        var inString = false
        var escaped = false
        for character in text[open...] {
            if inString {
                if escaped { escaped = false } else if character == "\\" { escaped = true } else if character == "\"" { inString = false }
                continue
            }
            switch character {
            case "\"": inString = true
            case "{", "[": depth += 1
            case "}", "]":
                depth -= 1
                if depth == 0 { return true }
            default: break
            }
        }
        return false
    }

    /// Removes Qwen-style `<think>…</think>` reasoning (including an unterminated block) before JSON parsing.
    nonisolated static func strippingThinkingBlocks(_ text: String) -> String {
        var result = text
        while let open = result.range(of: "<think>", options: .caseInsensitive) {
            if let close = result.range(of: "</think>", options: .caseInsensitive, range: open.upperBound..<result.endIndex) {
                result.removeSubrange(open.lowerBound..<close.upperBound)
            } else {
                result.removeSubrange(open.lowerBound..<result.endIndex)
            }
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func acquire() async {
        if !isBusy {
            isBusy = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        if waiters.isEmpty {
            isBusy = false
        } else {
            waiters.removeFirst().resume()
        }
    }

    #if !targetEnvironment(simulator)
    private func loadContainer(_ entry: ModelManager.CatalogEntry) async throws -> ModelContainer {
        if let container { return container }
        if let loadTask { return try await loadTask.value }

        let downloader = self.downloader
        let configuration = ModelConfiguration(id: entry.hfRepo, extraEOSTokens: entry.extraEOSTokens)
        let task = Task { () async throws -> ModelContainer in
            MLX.Memory.cacheLimit = Self.cacheLimitBytes
            // The snapshot is already in our cache (HubDownloader is pinned to local files), so this is the
            // no-network fast path: resolve the directory, load the weights, build the tokenizer. The LLM factory
            // is named explicitly instead of the free `loadModelContainer`, whose factory lookup goes through
            // `NSClassFromString("MLXLLM.TrampolineModelFactory")` and depends on the linker keeping that class.
            return try await LLMModelFactory.shared.loadContainer(
                from: downloader,
                using: TransformersTokenizerLoader(),
                configuration: configuration
            )
        }
        loadTask = task
        defer { loadTask = nil }
        do {
            // The load itself is not interruptible (mlx-swift-lm's resolve → loadWeights path has no cancellation
            // points), but forwarding cancellation keeps the handle honest and future-proof; `assess` checks
            // `Task.isCancelled` as soon as the weights are in.
            let loaded = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
            container = loaded
            logger.info("Loaded \(entry.hfRepo, privacy: .public)")
            return loaded
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            logger.error("Could not load \(entry.hfRepo, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw ClassifierError.unavailable("Could not load \(entry.displayName): \(error.localizedDescription)")
        }
    }

    private func unload() {
        guard container != nil else { return }
        container = nil
        MLX.Memory.clearCache()
        logger.info("Unloaded \(self.modelID, privacy: .public)")
    }

    /// Runs one greedy chat turn in an unstructured task whose handle is published to `generationHandle`, so the
    /// foreground gate can cancel it from the main thread the instant the app stops being frontmost — this actor
    /// is suspended awaiting the very generation that has to stop, so it cannot do the cancelling itself.
    /// mlx-swift-lm's token loop checks `Task.isCancelled` between tokens and submits nothing further.
    ///
    /// **Residual race.** Cancellation cannot un-submit a command buffer that is already queued. If the app resigns
    /// active in the window between "this token's buffers were submitted" and "the loop reaches its next
    /// cancellation check", that one in-flight buffer can still be rejected by iOS and terminate the process. The
    /// window is a single token (a few tens of milliseconds at most on the supported models) and it is entered only
    /// while a generation is already running; everything else — starting a generation, loading weights, prefilling
    /// a prompt — is prevented outright by the checks in `assess`. Nothing in the app can close that last gap; it
    /// needs a cancellation point inside MLX's command-buffer submission itself.
    private func generate(container: ModelContainer, prompt: String) async throws -> String {
        let task = Self.makeGenerationTask(container: container, instructions: PromptBuilder.systemPrompt, prompt: prompt)
        generationHandle.adopt(task)
        defer { generationHandle.clear() }
        // Closes the registration race: a gate that flipped between `checkForeground()` and `adopt` would have
        // found no task to cancel.
        if !foregroundGate.isForeground { task.cancel() }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }

    /// Created from a nonisolated context so the generation runs on the global executor rather than on this actor
    /// (which must stay free to answer `releaseResources()` while a scan is in flight). Nonisolated static so the
    /// non-Sendable `ChatSession` never crosses an isolation boundary.
    private nonisolated static func makeGenerationTask(
        container: ModelContainer,
        instructions: String,
        prompt: String
    ) -> Task<String, any Error> {
        Task {
            let parameters = GenerateParameters(maxTokens: maxTokens, maxKVSize: maxKVSize, temperature: 0)
            let session = ChatSession(container, instructions: instructions, generateParameters: parameters)
            let text = try await session.respond(to: prompt)
            await session.clear()
            return text
        }
    }
    #else
    private func unload() {}
    #endif
}

/// Cancellable handle on the generation currently on the GPU.
///
/// Lives outside the `MLXClassifier` actor on purpose: the foreground gate notifies its observers synchronously on
/// the main thread, and `Task.cancel()` only sets a flag, so the cancellation reaches the token loop without a hop
/// onto an actor that is itself waiting for that loop to finish.
final class GenerationHandle: Sendable {
    private let task = Mutex<Task<String, any Error>?>(nil)

    /// Publishes the running generation. Any previous one is cancelled (there can only be one: `assess` is
    /// serialised by the classifier actor).
    func adopt(_ generation: Task<String, any Error>) {
        let previous = task.withLock { slot -> Task<String, any Error>? in
            defer { slot = generation }
            return slot
        }
        previous?.cancel()
    }

    func clear() {
        task.withLock { $0 = nil }
    }

    /// Safe to call from any thread, including from inside a UIKit lifecycle notification.
    func cancel() {
        task.withLock { $0 }?.cancel()
    }
}
