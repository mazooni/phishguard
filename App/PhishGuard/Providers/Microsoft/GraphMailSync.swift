import Foundation
import OSLog
import PhishCore

/// The inbox delta loop: `/me/mailFolders/inbox/messages/delta` → hydrate each new message (body + headers,
/// attachment metadata) → `[EmailMessage]` sorted by `receivedDateTime`.
///
/// Pure networking logic with an injected `GraphClient` and bearer token so tests run against a `URLProtocol` stub.
struct GraphMailSync: Sendable {
    /// Fields on the delta entries (no body: bodies are fetched per message, so tombstones/echoes cost nothing).
    static let deltaSelect = "id,subject,from,sender,replyTo,toRecipients,receivedDateTime,hasAttachments,webLink,internetMessageId,isDraft,parentFolderId"
    /// Fields on the per-message GET. `internetMessageHeaders` is documented for GET only (research §4).
    static let messageSelect = "id,subject,from,sender,replyTo,toRecipients,receivedDateTime,hasAttachments,webLink,internetMessageId,conversationId,isDraft,body,internetMessageHeaders"
    /// Attachment metadata only; `contentBytes` is never requested.
    static let attachmentSelect = "name,contentType,size,isInline"
    static let deltaPath = "me/mailFolders/inbox/messages/delta"
    static let pageSize = 50
    /// Soft cap per scan on NEW (not yet processed) messages: paging stops at the first `@odata.nextLink` once this
    /// many were collected and that nextLink becomes the cursor, so nothing is skipped; the next scan resumes there.
    /// Must not exceed `ScanCoordinator.defaultMaxMessagesPerScan` (100), otherwise a capped batch can never be
    /// finished in one scan and every body is downloaded twice before the cursor advances.
    static let maxMessagesPerScan = 100
    /// Outlook allows 4 concurrent requests per app + mailbox (research §4).
    static let maxConcurrentRequests = 4

    static let deltaPreferences = [GraphClient.immutableIDPreference, "odata.maxpagesize=\(pageSize)"]
    static let messagePreferences = [GraphClient.immutableIDPreference]

    /// Graph error codes that mean the stored deltaLink can no longer be served.
    static let staleCursorCodes: Set<String> = ["syncstatenotfound", "resyncrequired", "syncstateinvalid", "errorinvalidsyncstatedata"]

    var client: GraphClient
    var now: @Sendable () -> Date

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "microsoft.sync")

    init(client: GraphClient, now: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.now = now
    }

    // MARK: - URLs

    /// The first delta request. Every query option lives here only: Graph encodes them into nextLink/deltaLink.
    func initialDeltaURL(lookback: TimeInterval) -> URL {
        let since = now().addingTimeInterval(-max(0, lookback))
        var components = URLComponents(url: GraphClient.url(for: Self.deltaPath), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "changeType", value: "created"),
            URLQueryItem(name: "$select", value: Self.deltaSelect),
            URLQueryItem(name: "$filter", value: "receivedDateTime ge \(GraphDate.string(from: since))"),
        ]
        return components.url!
    }

    static func messagePath(id: String) -> String {
        "me/messages/\(id)?$select=\(messageSelect)"
    }

    static func attachmentsPath(id: String) -> String {
        "me/messages/\(id)/attachments?$select=\(attachmentSelect)"
    }

    /// `410 Gone`, a known sync-state error code, or a `400` while following a stored link (stale token).
    static func isStaleCursorError(_ error: GraphError, followingStoredCursor: Bool) -> Bool {
        if error.status == 410 { return true }
        if let code = error.code?.lowercased(), staleCursorCodes.contains(code) { return true }
        return followingStoredCursor && error.status == 400
    }

    // MARK: - Delta

    struct DeltaRound: Sendable {
        var entries: [GraphMessage]
        var cursor: SyncCursor
        var cursorWasReset: Bool
    }

    func fetchNewMessages(
        accountID: UUID,
        token: String,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool = { _ in false }
    ) async throws -> FetchResult {
        let round = try await runDelta(token: token, cursor: cursor, lookback: lookback, isProcessed: isProcessed)
        let hydrated = try await hydrate(round.entries, accountID: accountID, token: token)
        let sorted = hydrated.sorted { $0.receivedAt < $1.receivedAt }
        logger.info("Delta round: \(round.entries.count) new entries, \(sorted.count) messages, reset=\(round.cursorWasReset)")
        return FetchResult(messages: sorted, cursor: round.cursor, cursorWasReset: round.cursorWasReset)
    }

    /// Follows the stored deltaLink (or starts a lookback-bounded delta), pages through `@odata.nextLink`,
    /// filters tombstones/drafts/echoes and already-processed ids (they are neither hydrated nor counted toward
    /// the cap) and returns the new cursor.
    func runDelta(
        token: String,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool = { _ in false }
    ) async throws -> DeltaRound {
        var url = cursor.map { GraphClient.url(for: $0.opaque) } ?? initialDeltaURL(lookback: lookback)
        var followingStoredCursor = cursor != nil
        var wasReset = false
        var isInitialSync = cursor == nil
        var entries: [GraphMessage] = []
        var seen = Set<String>()
        let lookbackFloor = now().addingTimeInterval(-max(0, lookback))

        while true {
            let page: GraphCollectionPage<GraphMessage>
            do {
                page = try await client.get(url.absoluteString, token: token, prefer: Self.deltaPreferences)
            } catch let error as GraphError {
                if Self.isStaleCursorError(error, followingStoredCursor: followingStoredCursor), !isInitialSync {
                    logger.notice("Delta cursor rejected (\(error.status)); restarting with the lookback window")
                    url = initialDeltaURL(lookback: lookback)
                    followingStoredCursor = false
                    wasReset = true
                    isInitialSync = true
                    entries.removeAll()
                    seen.removeAll()
                    continue
                }
                throw ProviderError(graph: error)
            }
            followingStoredCursor = false

            for entry in page.value where !entry.isTombstoneOrDraft {
                if isInitialSync, let received = entry.receivedDateTime, received < lookbackFloor { continue }
                if seen.insert(entry.id).inserted, !isProcessed(entry.id) { entries.append(entry) }
            }

            if let next = page.nextLink {
                if entries.count >= Self.maxMessagesPerScan {
                    // Resume from this page next time; nothing past it is lost.
                    return DeltaRound(entries: entries, cursor: SyncCursor(opaque: next), cursorWasReset: wasReset)
                }
                url = GraphClient.url(for: next)
                continue
            }
            let finalCursor = page.deltaLink ?? url.absoluteString
            return DeltaRound(entries: entries, cursor: SyncCursor(opaque: finalCursor), cursorWasReset: wasReset)
        }
    }

    // MARK: - Hydration

    /// Fetches body/headers (+ attachment metadata) for each entry with at most `maxConcurrentRequests` in flight.
    /// Messages that vanished in the meantime (404) are skipped; other failures abort the round so the cursor
    /// is not advanced past unscanned mail.
    func hydrate(_ entries: [GraphMessage], accountID: UUID, token: String) async throws -> [EmailMessage] {
        guard !entries.isEmpty else { return [] }
        return try await withThrowingTaskGroup(of: EmailMessage?.self) { group in
            var results: [EmailMessage] = []
            results.reserveCapacity(entries.count)
            var nextIndex = 0

            func enqueue() {
                guard nextIndex < entries.count else { return }
                let entry = entries[nextIndex]
                nextIndex += 1
                group.addTask { try await self.hydrate(entry, accountID: accountID, token: token) }
            }

            for _ in 0..<min(Self.maxConcurrentRequests, entries.count) { enqueue() }
            while let result = try await group.next() {
                if let result { results.append(result) }
                enqueue()
            }
            return results
        }
    }

    func hydrate(_ entry: GraphMessage, accountID: UUID, token: String) async throws -> EmailMessage? {
        let full: GraphMessage
        do {
            full = try await client.get(Self.messagePath(id: entry.id), token: token, prefer: Self.messagePreferences)
        } catch let error as GraphError where error.status == 404 {
            logger.notice("Message disappeared before it could be fetched; skipping")
            return nil
        } catch let error as GraphError {
            throw ProviderError(graph: error)
        }
        if full.isDraft == true { return nil }

        var attachments: [EmailAttachment] = []
        if full.hasAttachments == true || entry.hasAttachments == true {
            do {
                let page: GraphCollectionPage<GraphAttachment> = try await client.get(
                    Self.attachmentsPath(id: entry.id), token: token, prefer: Self.messagePreferences
                )
                attachments = GraphMessageMapper.mapAttachments(page.value)
            } catch let error as GraphError where error.status == 404 {
                attachments = []
            } catch let error as GraphError {
                throw ProviderError(graph: error)
            }
        }

        var merged = full
        if merged.receivedDateTime == nil { merged.receivedDateTime = entry.receivedDateTime }
        if merged.subject == nil { merged.subject = entry.subject }
        if merged.from == nil { merged.from = entry.from }
        if merged.webLink == nil { merged.webLink = entry.webLink }
        return try GraphMessageMapper.map(merged, accountID: accountID, attachments: attachments)
    }
}
