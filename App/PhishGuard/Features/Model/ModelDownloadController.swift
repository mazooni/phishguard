import Foundation
import Observation

/// The cancel entry point `ModelDownloadController` needs from the download manager (`ModelManager` conforms).
///
/// Cancelling has to go through the manager because the manager, not the screen, owns the in-flight download task:
/// a controller created after the user left and re-entered the Model screen has no task of its own to cancel.
@MainActor
protocol ModelDownloadCancelling: AnyObject {
    func cancelDownload(_ id: String)
}

extension ModelManager: ModelDownloadCancelling {}

/// View-side bookkeeping for `ModelManager` downloads: cancellable tasks, per-model error text and storage used.
/// `ModelManager` owns the on-disk state and the download tasks; this only tracks the in-flight `Task`s the UI
/// started, which are gone as soon as the screen is popped.
@MainActor
@Observable
final class ModelDownloadController {
    private var tasks: [String: Task<Void, Never>] = [:]
    private(set) var activeDownloadIDs: Set<String> = []
    private(set) var errorMessages: [String: String] = [:]
    private(set) var storageUsedBytes: Int64 = 0

    init() {}

    func isDownloading(_ id: String) -> Bool {
        activeDownloadIDs.contains(id)
    }

    func download(_ id: String, using manager: ModelManager) {
        guard tasks[id] == nil else { return }
        errorMessages[id] = nil
        activeDownloadIDs.insert(id)
        tasks[id] = Task { [weak self] in
            do {
                try await manager.download(id)
            } catch is CancellationError {
                // User cancelled: nothing to report.
            } catch {
                if !Task.isCancelled {
                    self?.errorMessages[id] = error.localizedDescription
                }
            }
            self?.tasks[id] = nil
            self?.activeDownloadIDs.remove(id)
            await self?.refreshStorage(using: manager)
        }
    }

    /// Stops a download, whether or not this controller instance started it: `tasks[id]` is empty in a controller
    /// created after the screen was re-entered, so the manager's own task is what must be cancelled.
    func cancel(_ id: String, using manager: any ModelDownloadCancelling) {
        tasks[id]?.cancel()
        tasks[id] = nil
        activeDownloadIDs.remove(id)
        manager.cancelDownload(id)
    }

    func delete(_ id: String, using manager: ModelManager) async {
        cancel(id, using: manager)
        do {
            try manager.delete(id)
            errorMessages[id] = nil
        } catch {
            errorMessages[id] = error.localizedDescription
        }
        await refreshStorage(using: manager)
    }

    func clearError(_ id: String) {
        errorMessages[id] = nil
    }

    /// Sums the files under the models directory on a background task.
    func refreshStorage(using manager: ModelManager) async {
        let directory = manager.modelsDirectory
        storageUsedBytes = await Task.detached(priority: .utility) {
            Self.directorySize(at: directory)
        }.value
    }

    nonisolated static func directorySize(at url: URL) -> Int64 {
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .fileSizeKey]
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]) else {
            return 0
        }
        var total: Int64 = 0
        for case let file as URL in enumerator {
            guard let values = try? file.resourceValues(forKeys: keys), values.isRegularFile == true else { continue }
            total += Int64(values.fileSize ?? 0)
        }
        return total
    }
}
