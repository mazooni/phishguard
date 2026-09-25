import Foundation
import OSLog
import SwiftData

/// ModelContainer factory. The schema lists every `@Model` in the app.
enum Persistence {
    static var schema: Schema {
        Schema([LinkedAccount.self, FlaggedEmailRecord.self, ProcessedMessage.self, FlaggedCallRecord.self])
    }

    /// Creates a container. `inMemory: true` is for previews and tests.
    static func makeContainer(inMemory: Bool = false) throws -> ModelContainer {
        if !inMemory {
            // SwiftData stores named configurations in Application Support; on a fresh install the directory does not
            // exist yet and CoreData logs a wall of "Failed to stat path" errors before creating it. Create it up front.
            if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            }
        }
        let configuration = ModelConfiguration("PhishGuard", schema: schema, isStoredInMemoryOnly: inMemory)
        return try ModelContainer(for: schema, configurations: [configuration])
    }

    /// The on-disk container for the running app. Falls back to an in-memory store if the disk store cannot be opened
    /// (e.g. an incompatible schema during development) so the app still launches.
    static func makeDefaultContainer() -> ModelContainer {
        let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "persistence")
        do {
            return try makeContainer()
        } catch {
            logger.error("Persistent store unavailable, falling back to in-memory: \(error.localizedDescription, privacy: .public)")
        }
        do {
            return try makeContainer(inMemory: true)
        } catch {
            fatalError("Unable to create any ModelContainer: \(error)")
        }
    }
}
