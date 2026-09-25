import Foundation
import HuggingFace
import Observation
import OSLog

/// Catalog of downloadable MLX models plus their on-disk state.
///
/// Models live in a Hugging Face-compatible cache (`HubCache`) under
/// `Application Support/PhishGuard/models/models--<org>--<name>/{blobs,refs,snapshots}`, which is excluded from
/// iCloud backup. Downloads go through `HubClient.downloadSnapshot`, which resumes partially downloaded blobs
/// (`<etag>.incomplete` + HTTP `Range`) and skips files that are already complete, so a cancelled download picks up
/// where it left off the next time.
@MainActor
@Observable
final class ModelManager {
    struct CatalogEntry: Identifiable, Sendable, Hashable {
        let id: String
        let displayName: String
        /// Hugging Face repository (mlx-community conversions, verified 2026-09-21).
        let hfRepo: String
        /// Sum of the repository's files (decimal bytes, from the Hugging Face API).
        let approxSizeBytes: Int64
        let notes: String
        /// Installed RAM the model is comfortable on (nominal, see `ModelManager.meetsRAMRequirement`).
        let minimumRecommendedRAMBytes: Int64
        /// End-of-turn tokens merged into the tokenizer's EOS set (`ModelConfiguration.extraEOSTokens`).
        let extraEOSTokens: Set<String>
        /// Hybrid "thinking" model: PhishGuard appends `/no_think` to every prompt and strips `<think>` blocks.
        let isThinkingModel: Bool

        /// Memory the loaded model needs: 4-bit weights plus KV cache and activations for a ~1.5k-token prompt.
        var estimatedRuntimeBytes: Int64 { ModelManager.estimatedRuntimeBytes(forDownloadSize: approxSizeBytes) }
    }

    enum DownloadState: Sendable, Equatable {
        case notDownloaded
        case downloading(progress: Double)
        case downloaded
        case failed(String)
    }

    nonisolated static let gibibyte: Int64 = 1_073_741_824
    /// Devices report a little less than their nominal RAM; allow this much slack when comparing.
    nonisolated static let ramTolerance: Int64 = 768 * 1024 * 1024
    /// Same globs MLXLMCommon uses for model snapshots.
    nonisolated static let downloadPatterns = ["*.safetensors", "*.json", "*.jinja"]

    /// The model PhishGuard ships with: Qwen3 4B Instruct 2507, downloaded during onboarding and used by
    /// `ClassifierChoice.mlx` unless the user picks another catalog entry. Catalog order below is preference
    /// order, so this is also the first row on the Model settings screen.
    ///
    /// It used to be the 1.7B. That model misjudged real mail in the field (2026-09), and accuracy on a
    /// watchdog that only speaks up when something is wrong is worth more than the extra ~1.3 GB of download:
    /// the 4B is a non-thinking instruct model, so it never spends tokens on `<think>` blocks and returns the
    /// JSON schema far more reliably. The 1.7B stays in the catalog one tap away as the smaller, faster option
    /// (and the sensible pick on a 6 GB iPhone — see `meetsRAMRequirement`).
    nonisolated static let defaultModelID = "qwen3-4b-instruct-2507-4bit"

    nonisolated static let catalog: [CatalogEntry] = [
        CatalogEntry(
            id: "qwen3-4b-instruct-2507-4bit",
            displayName: "Qwen3 4B",
            hfRepo: "mlx-community/Qwen3-4B-Instruct-2507-4bit",
            approxSizeBytes: 2_278_972_236,
            notes: "PhishGuard's default: the most accurate model of this size, with the best instruction "
                + "following and JSON output, and it never emits thinking blocks. Needs an 8 GB iPhone "
                + "(iPhone 16 or newer) and about 2.6 GB of memory while running.",
            minimumRecommendedRAMBytes: 8 * gibibyte,
            extraEOSTokens: ["<|im_end|>"],
            isThinkingModel: false
        ),
        CatalogEntry(
            id: "qwen3-1.7b-4bit",
            displayName: "Qwen3 1.7B",
            hfRepo: "mlx-community/Qwen3-1.7B-4bit",
            approxSizeBytes: 984_015_687,
            notes: "Smaller and faster than the default, and less accurate: it reads an email properly but "
                + "misjudges the subtler ones. About 1.3 GB while running, so it is the pick for a 6 GB iPhone "
                + "or a tight data plan. Hybrid thinking model: PhishGuard turns thinking off for every request.",
            minimumRecommendedRAMBytes: 6 * gibibyte,
            extraEOSTokens: ["<|im_end|>"],
            isThinkingModel: true
        ),
        CatalogEntry(
            id: "llama-3.2-3b-instruct-4bit",
            displayName: "Llama 3.2 3B Instruct",
            hfRepo: "mlx-community/Llama-3.2-3B-Instruct-4bit",
            approxSizeBytes: 1_824_825_759,
            notes: "Smaller and faster than the default, and less accurate: reliable JSON and decent speed, "
                + "about 2.1 GB while running. A middle step between the two Qwen models.",
            minimumRecommendedRAMBytes: 6 * gibibyte,
            extraEOSTokens: ["<|eot_id|>"],
            isThinkingModel: false
        ),
        CatalogEntry(
            id: "gemma-3-text-4b-it-4bit",
            displayName: "Gemma 3 4B Instruct (text only)",
            hfRepo: "mlx-community/gemma-3-text-4b-it-4bit",
            approxSizeBytes: 2_600_191_231,
            notes: "Larger, more accurate: strong general quality, but the heaviest model here (about 2.9 GB while "
                + "running); 8 GB iPhones only.",
            minimumRecommendedRAMBytes: 8 * gibibyte,
            extraEOSTokens: ["<end_of_turn>"],
            isThinkingModel: false
        ),
        CatalogEntry(
            id: "gemma-3-1b-it-4bit",
            displayName: "Gemma 3 1B Instruct (smallest)",
            hfRepo: "mlx-community/gemma-3-1b-it-4bit",
            approxSizeBytes: 771_863_590,
            notes: "Smaller than the default and noticeably less accurate; a last-resort tier for 4 GB iPhones.",
            minimumRecommendedRAMBytes: 4 * gibibyte,
            extraEOSTokens: ["<end_of_turn>"],
            isThinkingModel: false
        ),
    ]

    private(set) var downloadStates: [String: DownloadState] = [:]
    /// Root of the Hugging Face-style cache (`HubCache.cacheDirectory`).
    let modelsDirectory: URL
    nonisolated let cache: HubCache
    nonisolated let hub: HubClient

    @ObservationIgnored private var downloadTasks: [String: Task<URL, any Error>] = [:]
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "models")

    init(modelsDirectory: URL? = nil) {
        let directory = modelsDirectory ?? Self.defaultModelsDirectory()
        Self.prepareDirectory(directory)
        let cache = HubCache(cacheDirectory: directory)
        self.modelsDirectory = directory
        self.cache = cache
        self.hub = HubClient(cache: cache)
        refreshStates()
    }

    // MARK: - Catalog

    nonisolated static func entry(for id: String) -> CatalogEntry? {
        catalog.first { $0.id == id }
    }

    nonisolated static func entry(forRepo repo: String) -> CatalogEntry? {
        catalog.first { $0.hfRepo == repo }
    }

    /// The catalog entry to suggest, which is `defaultModelID` (Qwen3 4B) on every device.
    ///
    /// PhishGuard used to scale this with installed RAM. It no longer does: the local model is the classifier
    /// the app leans on, onboarding downloads it before the first account is linked, and a recommendation that
    /// differs per device would mean two different detectors in the field. Accuracy decides it, so every device
    /// is pointed at the 4B; on a 6 GB iPhone `meetsRAMRequirement` and `DeviceModelRecommendation` still say so
    /// (the Model screen warns, and Qwen3 1.7B is the entry to fall back to). `physicalMemoryBytes` is kept so
    /// callers (and tests) can ask about a specific device.
    nonisolated static func recommendedModelID(
        physicalMemoryBytes: UInt64 = ProcessInfo.processInfo.physicalMemory
    ) -> String {
        defaultModelID
    }

    /// Whether a device with `physicalMemoryBytes` meets the entry's recommended RAM (with `ramTolerance` slack).
    nonisolated static func meetsRAMRequirement(_ entry: CatalogEntry, physicalMemoryBytes: UInt64) -> Bool {
        Int64(clamping: physicalMemoryBytes) + ramTolerance >= entry.minimumRecommendedRAMBytes
    }

    /// Weights + ~12 % for the 4-bit scales/biases and embeddings + 320 MB for KV cache, activations and the
    /// Metal buffer cache (`Memory.cacheLimit` = 20 MB).
    nonisolated static func estimatedRuntimeBytes(forDownloadSize bytes: Int64) -> Int64 {
        bytes + bytes / 8 + 320 * 1024 * 1024
    }

    // MARK: - Directories

    nonisolated static func defaultModelsDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appending(path: "PhishGuard/models", directoryHint: .isDirectory)
    }

    /// Creates the directory and excludes it from iCloud/iTunes backup (multi-GB weights are re-downloadable).
    nonisolated static func prepareDirectory(_ directory: URL) {
        var directory = directory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? directory.setResourceValues(values)
    }

    /// The repository directory inside the cache (`models--<org>--<name>`). For ids not in the catalog this is
    /// `modelsDirectory/<id>` so callers always get a usable path.
    func modelDirectory(for id: String) -> URL {
        if let entry = Self.entry(for: id), let repo = Repo.ID(rawValue: entry.hfRepo) {
            return cache.repoDirectory(repo: repo, kind: .model)
        }
        return modelsDirectory.appending(path: id, directoryHint: .isDirectory)
    }

    /// The snapshot directory that holds `config.json` and the weights, or nil when the model is not fully present.
    func snapshotDirectory(for id: String) -> URL? {
        guard let entry = Self.entry(for: id) else { return nil }
        return Self.snapshotDirectory(forRepo: entry.hfRepo, in: cache)
    }

    /// Resolves `refs/main` → `snapshots/<commit>` and requires `requiredSnapshotFiles` plus at least one
    /// `.safetensors`.
    nonisolated static func snapshotDirectory(forRepo repo: String, in cache: HubCache) -> URL? {
        guard let repoID = Repo.ID(rawValue: repo),
              let commit = cache.resolveRevision(repo: repoID, kind: .model, ref: "main"),
              !commit.isEmpty,
              let snapshot = try? cache.snapshotPath(repo: repoID, kind: .model, commitHash: commit),
              looksComplete(snapshot)
        else { return nil }
        return snapshot
    }

    nonisolated static func isDownloaded(repo: String, in cache: HubCache) -> Bool {
        snapshotDirectory(forRepo: repo, in: cache) != nil
    }

    /// Files the model cannot load without: `config.json` for MLXLMCommon's factory, and the two tokenizer files
    /// swift-transformers' `AutoTokenizer.from(modelFolder:)` reads (`tokenizer.model` is not in
    /// `downloadPatterns`, so `tokenizer.json` is the only tokenizer data file a snapshot can have).
    nonisolated static let requiredSnapshotFiles = ["config.json", "tokenizer.json", "tokenizer_config.json"]

    /// Whether a snapshot directory holds a model that can actually be loaded. A snapshot with the weights but
    /// without a tokenizer would otherwise count as downloaded while every classification fails in the tokenizer
    /// loader, and `download()` would short-circuit instead of fetching the missing files.
    nonisolated static func looksComplete(_ directory: URL) -> Bool {
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return false }
        let names = Set(contents)
        return requiredSnapshotFiles.allSatisfy(names.contains) && contents.contains { $0.hasSuffix(".safetensors") }
    }

    // MARK: - State

    func isDownloaded(_ id: String) -> Bool {
        guard let entry = Self.entry(for: id) else { return false }
        return Self.isDownloaded(repo: entry.hfRepo, in: cache)
    }

    /// Re-reads the on-disk state for every catalog entry (in-flight downloads keep their state).
    func refreshStates() {
        for entry in Self.catalog {
            if case .downloading = downloadStates[entry.id] { continue }
            downloadStates[entry.id] = isDownloaded(entry.id) ? .downloaded : .notDownloaded
        }
    }

    /// Bytes used by every model file under `modelsDirectory` (symlinks in snapshots are not double-counted).
    var storageUsedBytes: Int64 {
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        guard let enumerator = FileManager.default.enumerator(
            at: modelsDirectory, includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]
        ) else { return 0 }
        var total: Int64 = 0
        for case let url as URL in enumerator {
            guard let values = try? url.resourceValues(forKeys: keys),
                  values.isRegularFile == true, values.isSymbolicLink != true
            else { continue }
            total += Int64(values.fileSize ?? 0)
        }
        return total
    }

    // MARK: - Download / delete

    /// Downloads the model's snapshot (`*.safetensors`, `*.json`, `*.jinja`) into the cache, reporting progress
    /// through `downloadStates[id]`. Joins an in-flight download of the same model. Cancel with `cancelDownload`
    /// (or by cancelling the calling task): the state returns to `.notDownloaded`, partial blobs stay on disk and
    /// resume on the next call. A snapshot that is on disk but incomplete (see `looksComplete`) is not short-
    /// circuited: `downloadSnapshot` serves the files already in the cache and fetches only the missing ones.
    func download(_ id: String) async throws {
        guard let entry = Self.entry(for: id) else { throw ClassifierError.unavailable("Unknown model \"\(id)\".") }
        if let inFlight = downloadTasks[id] {
            _ = try await inFlight.value
            return
        }
        if isDownloaded(id) {
            downloadStates[id] = .downloaded
            return
        }
        guard let repo = Repo.ID(rawValue: entry.hfRepo) else {
            throw ClassifierError.unavailable("Invalid repository id \"\(entry.hfRepo)\".")
        }

        downloadStates[id] = .downloading(progress: 0)
        logger.info("Downloading \(entry.hfRepo, privacy: .public)")
        let hub = self.hub
        let task = Task { [weak self] () async throws -> URL in
            try await hub.downloadSnapshot(
                of: repo,
                kind: .model,
                revision: "main",
                matching: Self.downloadPatterns,
                progressHandler: { @MainActor progress in
                    guard let self, case .downloading = self.downloadStates[id] else { return }
                    self.downloadStates[id] = .downloading(progress: min(max(progress.fractionCompleted, 0), 1))
                }
            )
        }
        downloadTasks[id] = task
        defer { downloadTasks[id] = nil }

        do {
            let snapshot = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
            guard Self.looksComplete(snapshot) else {
                downloadStates[id] = .failed("The download finished but the model files are incomplete. Try again.")
                throw ClassifierError.unavailable("Incomplete download for \(entry.displayName).")
            }
            downloadStates[id] = .downloaded
            logger.info("Downloaded \(entry.hfRepo, privacy: .public)")
        } catch {
            guard !Self.isCancellation(error, taskWasCancelled: task.isCancelled) else {
                downloadStates[id] = .notDownloaded
                logger.notice("Download cancelled: \(entry.hfRepo, privacy: .public)")
                return
            }
            downloadStates[id] = .failed(error.localizedDescription)
            logger.error("Download failed for \(entry.hfRepo, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    /// Every shape a cancelled download arrives in. swift-huggingface reacts to cancellation by cancelling its
    /// `URLSessionDownloadTask`, whose delegate resumes the continuation with `URLError.cancelled` (-999) and never
    /// with `CancellationError`, so cancelling must not be reported to the user as a failed download.
    /// `taskWasCancelled` is the inner download task's own flag: `cancelDownload`/`delete` cancel it without
    /// cancelling the caller.
    nonisolated static func isCancellation(_ error: any Error, taskWasCancelled: Bool) -> Bool {
        taskWasCancelled || error is CancellationError || (error as? URLError)?.code == .cancelled
    }

    /// Cancels an in-flight download; partial files are kept for a later resume. The manager owns the task, so this
    /// works from any screen — including a `ModelDownloadController` created after the Model screen was re-entered.
    func cancelDownload(_ id: String) {
        downloadTasks[id]?.cancel()
    }

    /// Removes the whole repository directory (blobs, refs and snapshots).
    func delete(_ id: String) throws {
        guard let entry = Self.entry(for: id) else { throw ClassifierError.unavailable("Unknown model \"\(id)\".") }
        cancelDownload(id)
        let directory = modelDirectory(for: id)
        if FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.removeItem(at: directory)
        }
        downloadStates[id] = .notDownloaded
        logger.info("Deleted model \(entry.hfRepo, privacy: .public)")
    }
}
