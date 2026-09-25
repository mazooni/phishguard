import Foundation
import XCTest
@testable import PhishGuard

/// Catalog, recommendation and on-disk logic of `ModelManager` on a temporary directory; no network is touched.
@MainActor
final class ModelManagerTests: XCTestCase {
    private var directory: URL!

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appending(path: "ModelManagerTests-\(UUID().uuidString)", directoryHint: .isDirectory)
    }

    override func tearDown() async throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    // MARK: - Catalog

    func testCatalogMatchesResearch() {
        let catalog = ModelManager.catalog
        // Catalog order is preference order, so the default entry comes first.
        XCTAssertEqual(catalog.map(\.hfRepo), [
            "mlx-community/Qwen3-4B-Instruct-2507-4bit",
            "mlx-community/Qwen3-1.7B-4bit",
            "mlx-community/Llama-3.2-3B-Instruct-4bit",
            "mlx-community/gemma-3-text-4b-it-4bit",
            "mlx-community/gemma-3-1b-it-4bit",
        ])
        XCTAssertEqual(catalog.first?.id, ModelManager.defaultModelID)
        XCTAssertEqual(Set(catalog.map(\.id)).count, catalog.count, "ids are unique")
        for entry in catalog {
            XCTAssertGreaterThan(entry.approxSizeBytes, 500_000_000, entry.id)
            XCTAssertLessThan(entry.approxSizeBytes, 3_000_000_000, entry.id)
            XCTAssertGreaterThanOrEqual(entry.minimumRecommendedRAMBytes, 4 * ModelManager.gibibyte, entry.id)
            XCTAssertFalse(entry.notes.isEmpty, entry.id)
            XCTAssertFalse(entry.extraEOSTokens.isEmpty, entry.id)
            XCTAssertGreaterThan(entry.estimatedRuntimeBytes, entry.approxSizeBytes, entry.id)
            XCTAssertNotNil(ModelManager.entry(for: entry.id))
            XCTAssertEqual(ModelManager.entry(forRepo: entry.hfRepo)?.id, entry.id)
        }
        XCTAssertEqual(catalog.filter(\.isThinkingModel).map(\.id), ["qwen3-1.7b-4bit"])
        XCTAssertEqual(ModelManager.entry(for: "qwen3-4b-instruct-2507-4bit")?.extraEOSTokens, ["<|im_end|>"])
        XCTAssertEqual(ModelManager.entry(for: "llama-3.2-3b-instruct-4bit")?.extraEOSTokens, ["<|eot_id|>"])
        XCTAssertEqual(ModelManager.entry(for: "gemma-3-text-4b-it-4bit")?.extraEOSTokens, ["<end_of_turn>"])
        XCTAssertNil(ModelManager.entry(for: "does-not-exist"))
    }

    /// The notes are the only place the Model screen explains why a user would leave the default, so they have to
    /// keep saying which entry is the default and which way each other entry trades size for accuracy. The default
    /// is now the 4B, so every remaining entry but the Gemma 4B is a step *down* in accuracy.
    func testCatalogNotesNameTheDefaultAndPlaceEveryOtherEntryAgainstIt() throws {
        let entryDefault = try XCTUnwrap(ModelManager.entry(for: ModelManager.defaultModelID))
        XCTAssertEqual(entryDefault.id, "qwen3-4b-instruct-2507-4bit")
        XCTAssertTrue(entryDefault.notes.localizedCaseInsensitiveContains("default"), entryDefault.notes)
        // The row carries a "Recommended" capsule next to the name, so the name itself stays short.
        XCTAssertLessThanOrEqual(entryDefault.displayName.count, 16, entryDefault.displayName)

        for id in ["qwen3-1.7b-4bit", "llama-3.2-3b-instruct-4bit", "gemma-3-1b-it-4bit"] {
            let entry = try XCTUnwrap(ModelManager.entry(for: id))
            XCTAssertLessThan(entry.approxSizeBytes, entryDefault.approxSizeBytes, id)
            XCTAssertTrue(entry.notes.localizedCaseInsensitiveContains("smaller"), "\(id): \(entry.notes)")
            XCTAssertTrue(entry.notes.localizedCaseInsensitiveContains("less accurate"), "\(id): \(entry.notes)")
            XCTAssertFalse(entry.displayName.localizedCaseInsensitiveContains("recommended"), entry.displayName)
        }

        let gemma4B = try XCTUnwrap(ModelManager.entry(for: "gemma-3-text-4b-it-4bit"))
        XCTAssertGreaterThan(gemma4B.approxSizeBytes, entryDefault.approxSizeBytes)
        XCTAssertTrue(gemma4B.notes.localizedCaseInsensitiveContains("larger"), gemma4B.notes)
        XCTAssertTrue(gemma4B.notes.localizedCaseInsensitiveContains("accurate"), gemma4B.notes)
    }

    /// The recommendation is the same entry on every device rather than the biggest one the device could hold:
    /// onboarding downloads it before the first account is linked, and accuracy — not installed RAM — decides
    /// which model that is. The RAM helpers stay exactly as they were: they still report that the 4B wants an
    /// 8 GB iPhone, which is what makes the Model screen warn before a manual pick and what points a 6 GB
    /// device at Qwen3 1.7B.
    func testRecommendedModelIsTheDefaultOnEveryDevice() {
        let gib = UInt64(ModelManager.gibibyte)
        for ram in [12 * gib, 8 * gib, UInt64(7_900_000_000), 6 * gib, UInt64(5_700_000_000), 4 * gib, 0] {
            XCTAssertEqual(ModelManager.recommendedModelID(physicalMemoryBytes: ram), "qwen3-4b-instruct-2507-4bit", "\(ram) bytes")
        }
        XCTAssertEqual(ModelManager.recommendedModelID(), ModelManager.defaultModelID)
        XCTAssertNotNil(ModelManager.entry(for: ModelManager.recommendedModelID()), "the live recommendation is a catalog entry")

        // The memory helpers keep working and keep their old answers.
        let fourB = ModelManager.entry(for: "qwen3-4b-instruct-2507-4bit")!
        XCTAssertTrue(ModelManager.meetsRAMRequirement(fourB, physicalMemoryBytes: 8 * gib))
        XCTAssertTrue(ModelManager.meetsRAMRequirement(fourB, physicalMemoryBytes: 7_900_000_000), "the RAM tolerance still applies")
        XCTAssertFalse(ModelManager.meetsRAMRequirement(fourB, physicalMemoryBytes: 6 * gib))

        // The smaller option every supported iPhone can hold is still in the catalog, right behind the default.
        let smaller = ModelManager.entry(for: "qwen3-1.7b-4bit")!
        XCTAssertEqual(ModelManager.catalog[1].id, smaller.id, "catalog order is preference order")
        XCTAssertTrue(ModelManager.meetsRAMRequirement(smaller, physicalMemoryBytes: 6 * gib))
        XCTAssertLessThan(smaller.approxSizeBytes, fourB.approxSizeBytes)

        let defaultEntry = ModelManager.entry(for: ModelManager.defaultModelID)!
        XCTAssertEqual(defaultEntry.approxSizeBytes, 2_278_972_236, "the Qwen3-4B-Instruct-2507-4bit repo is 2.28 GB")
        XCTAssertFalse(defaultEntry.isThinkingModel, "the default must never emit <think> blocks")
    }

    func testEstimatedRuntimeBytesAddsOverhead() {
        let runtime = ModelManager.estimatedRuntimeBytes(forDownloadSize: 2_000_000_000)
        XCTAssertEqual(runtime, 2_000_000_000 + 250_000_000 + 320 * 1024 * 1024)
    }

    // MARK: - Directories and state

    func testInitCreatesExcludedDirectoryAndReadsStates() throws {
        let manager = ModelManager(modelsDirectory: directory)
        XCTAssertEqual(manager.modelsDirectory, directory)
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
        let values = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)

        XCTAssertEqual(manager.downloadStates.count, ModelManager.catalog.count)
        for entry in ModelManager.catalog {
            XCTAssertEqual(manager.downloadStates[entry.id], .notDownloaded)
            XCTAssertFalse(manager.isDownloaded(entry.id))
            XCTAssertNil(manager.snapshotDirectory(for: entry.id))
        }
        XCTAssertEqual(manager.storageUsedBytes, 0)
        XCTAssertFalse(manager.isDownloaded("unknown"))
        XCTAssertEqual(manager.modelDirectory(for: "unknown").lastPathComponent, "unknown")
    }

    func testModelDirectoryUsesHuggingFaceCacheLayout() {
        let manager = ModelManager(modelsDirectory: directory)
        let repoDirectory = manager.modelDirectory(for: "qwen3-1.7b-4bit")
        XCTAssertEqual(repoDirectory.lastPathComponent, "models--mlx-community--Qwen3-1.7B-4bit")
        XCTAssertEqual(repoDirectory.deletingLastPathComponent().standardizedFileURL, directory.standardizedFileURL)
    }

    func testIsDownloadedRequiresConfigAndWeightsInResolvedSnapshot() throws {
        let manager = ModelManager(modelsDirectory: directory)
        let id = "qwen3-1.7b-4bit"
        let repoDirectory = manager.modelDirectory(for: id)
        let commit = "0123456789abcdef0123456789abcdef01234567"
        let snapshot = repoDirectory.appending(path: "snapshots/\(commit)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: snapshot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: repoDirectory.appending(path: "refs"), withIntermediateDirectories: true)

        // No ref yet → not downloaded even though files exist.
        for name in ModelManager.requiredSnapshotFiles {
            try Data("{}".utf8).write(to: snapshot.appending(path: name))
        }
        try Data(repeating: 0, count: 4096).write(to: snapshot.appending(path: "model.safetensors"))
        XCTAssertFalse(manager.isDownloaded(id))

        // Ref present but pointing at a missing snapshot → not downloaded.
        try "deadbeef\n".write(to: repoDirectory.appending(path: "refs/main"), atomically: true, encoding: .utf8)
        XCTAssertFalse(manager.isDownloaded(id))

        // Ref resolves to the snapshot → downloaded.
        try "\(commit)\n".write(to: repoDirectory.appending(path: "refs/main"), atomically: true, encoding: .utf8)
        XCTAssertTrue(manager.isDownloaded(id))
        XCTAssertEqual(manager.snapshotDirectory(for: id)?.lastPathComponent, commit)
        XCTAssertTrue(ModelManager.isDownloaded(repo: "mlx-community/Qwen3-1.7B-4bit", in: manager.cache))
        XCTAssertFalse(ModelManager.isDownloaded(repo: "mlx-community/gemma-3-1b-it-4bit", in: manager.cache))
        XCTAssertGreaterThanOrEqual(manager.storageUsedBytes, 4096 + 2)

        // #43: a snapshot the tokenizer loader cannot use is not "downloaded", so `download()` stops short-
        // circuiting and `downloadSnapshot` refetches just the missing file instead of the whole 1-3 GB repo.
        for name in ModelManager.requiredSnapshotFiles where name != "config.json" {
            let file = snapshot.appending(path: name)
            try FileManager.default.removeItem(at: file)
            XCTAssertFalse(manager.isDownloaded(id), "\(name) is required to load the model")
            XCTAssertNil(manager.snapshotDirectory(for: id))
            manager.refreshStates()
            XCTAssertEqual(manager.downloadStates[id], .notDownloaded)
            try Data("{}".utf8).write(to: file)
            XCTAssertTrue(manager.isDownloaded(id))
        }

        // Weights removed → incomplete.
        try FileManager.default.removeItem(at: snapshot.appending(path: "model.safetensors"))
        XCTAssertFalse(manager.isDownloaded(id))
        try Data(repeating: 1, count: 16).write(to: snapshot.appending(path: "model-00001-of-00002.safetensors"))
        XCTAssertTrue(manager.isDownloaded(id))
        try FileManager.default.removeItem(at: snapshot.appending(path: "config.json"))
        XCTAssertFalse(manager.isDownloaded(id))
    }

    func testRefreshStatesDeleteAndDownloadShortCircuit() async throws {
        let manager = ModelManager(modelsDirectory: directory)
        let id = "gemma-3-1b-it-4bit"
        try makeFakeSnapshot(manager: manager, id: id, commit: "abc123")

        XCTAssertEqual(manager.downloadStates[id], .notDownloaded, "states are read at init; the fake was added afterwards")
        manager.refreshStates()
        XCTAssertEqual(manager.downloadStates[id], .downloaded)

        // Already on disk → download returns immediately without touching the network.
        try await manager.download(id)
        XCTAssertEqual(manager.downloadStates[id], .downloaded)

        manager.cancelDownload(id) // nothing in flight: no-op
        try manager.delete(id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: manager.modelDirectory(for: id).path))
        XCTAssertEqual(manager.downloadStates[id], .notDownloaded)
        XCTAssertFalse(manager.isDownloaded(id))
        XCTAssertEqual(manager.storageUsedBytes, 0)
    }

    /// #16: cancelling a download must land in `.notDownloaded`. swift-huggingface cancels its
    /// `URLSessionDownloadTask`, which surfaces as `URLError.cancelled` (-999) rather than `CancellationError`, so
    /// the old `catch is CancellationError` branch was never taken and the row showed a red "-999" failure.
    func testCancellationIsRecognisedInEveryShapeItArrivesIn() {
        XCTAssertTrue(ModelManager.isCancellation(CancellationError(), taskWasCancelled: false))
        XCTAssertTrue(ModelManager.isCancellation(URLError(.cancelled), taskWasCancelled: false),
                      "what the library actually throws when the UI taps Cancel")
        XCTAssertTrue(ModelManager.isCancellation(URLError(.timedOut), taskWasCancelled: true),
                      "cancelDownload/delete cancel the inner task without cancelling the caller")
        XCTAssertFalse(ModelManager.isCancellation(URLError(.timedOut), taskWasCancelled: false))
        XCTAssertFalse(ModelManager.isCancellation(URLError(.notConnectedToInternet), taskWasCancelled: false))
        XCTAssertFalse(ModelManager.isCancellation(ClassifierError.unavailable("boom"), taskWasCancelled: false))
    }

    /// #21: a `ModelDownloadController` created after the user left and re-entered the Model screen has no task of
    /// its own, so Cancel must reach the manager, which owns the in-flight download.
    func testCancelReachesTheManagerEvenWhenAnotherControllerStartedTheDownload() {
        final class CancelSpy: ModelDownloadCancelling {
            var cancelled: [String] = []
            func cancelDownload(_ id: String) { cancelled.append(id) }
        }
        let spy = CancelSpy()
        let freshController = ModelDownloadController()   // never started a download: `tasks` is empty
        XCTAssertFalse(freshController.isDownloading("qwen3-1.7b-4bit"))

        freshController.cancel("qwen3-1.7b-4bit", using: spy)
        XCTAssertEqual(spy.cancelled, ["qwen3-1.7b-4bit"])
        XCTAssertFalse(freshController.isDownloading("qwen3-1.7b-4bit"))
    }

    func testUnknownModelIsRejected() async {
        let manager = ModelManager(modelsDirectory: directory)
        do {
            try await manager.download("nope")
            XCTFail("expected an error")
        } catch let error as ClassifierError {
            guard case .unavailable = error else { return XCTFail("unexpected \(error)") }
        } catch {
            XCTFail("unexpected \(error)")
        }
        XCTAssertThrowsError(try manager.delete("nope"))
        XCTAssertNil(manager.downloadStates["nope"])
    }

    // MARK: - Helpers

    private func makeFakeSnapshot(manager: ModelManager, id: String, commit: String) throws {
        let repoDirectory = manager.modelDirectory(for: id)
        let snapshot = repoDirectory.appending(path: "snapshots/\(commit)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: snapshot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: repoDirectory.appending(path: "refs"), withIntermediateDirectories: true)
        try "\(commit)\n".write(to: repoDirectory.appending(path: "refs/main"), atomically: true, encoding: .utf8)
        for name in ModelManager.requiredSnapshotFiles {
            try Data("{}".utf8).write(to: snapshot.appending(path: name))
        }
        try Data(repeating: 0, count: 1024).write(to: snapshot.appending(path: "model.safetensors"))
    }
}
