import Foundation
import OSLog
import PhishCore
import UIKit

/// Where an IMAP account's sync stands: the mailbox generation (`UIDVALIDITY`) and the highest UID already
/// handed to the scanner. Serialised into `SyncCursor.opaque` as `"<uidvalidity>:<uid>"`.
struct IMAPSyncCursor: Sendable, Equatable {
    var uidValidity: UInt32
    var lastUID: UInt32

    init(uidValidity: UInt32, lastUID: UInt32) {
        self.uidValidity = uidValidity
        self.lastUID = lastUID
    }

    init?(opaque: String) {
        let parts = opaque.split(separator: ":", maxSplits: 1)
        guard parts.count == 2, let validity = UInt32(parts[0]), let uid = UInt32(parts[1]) else { return nil }
        self.init(uidValidity: validity, lastUID: uid)
    }

    var opaque: String { "\(uidValidity):\(lastUID)" }
    var syncCursor: SyncCursor { SyncCursor(opaque: opaque) }
}

/// Reads any IMAP mailbox — iCloud, Yahoo, Fastmail, AOL, GMX, Zoho, a custom domain — with the same
/// read-only contract as the OAuth providers.
///
/// Differences from Gmail/Graph, all forced by the protocol:
/// * `signIn` is not OAuth. It presents `IMAPSetupView`, then proves the credentials work by connecting,
///   authenticating and issuing `EXAMINE INBOX` before anything is stored.
/// * The cursor is `UIDVALIDITY:lastUID`. A changed `UIDVALIDITY` means the server renumbered the mailbox, so
///   the cursor is dropped and the fetch falls back to the lookback window with `cursorWasReset` set.
/// * There is no push. `ensurePushSubscription` always throws `ProviderError.pushNotSupported`, which the scan
///   coordinator treats as an expected condition; these accounts are scanned in the foreground and by
///   background refresh.
actor IMAPProvider: MailAccountProvider {
    nonisolated let provider: MailProvider = .imap

    /// Upper bound on NEW (not yet processed) messages per fetch. Must not exceed
    /// `ScanCoordinator.defaultMaxMessagesPerScan`, otherwise a capped batch can never be finished in one scan.
    static let maxMessagesPerFetch = 100
    /// How many uids are asked for in one `UID FETCH`.
    static let metadataChunkSize = 50
    /// Messages up to this size are downloaded whole (`BODY.PEEK[]`) and handed to `MIMEParser`.
    static let maxWholeMessageBytes = 512 * 1024
    /// Above that, only the header block and the inline text parts are fetched, each capped at this size, so an
    /// attachment's bytes are never downloaded.
    static let maxPartBytes = 256 * 1024
    /// Total body bytes one fetch may download before the rest of the batch falls back to headers only.
    static let maxTotalDownloadBytes = 16 * 1024 * 1024

    private let store: IMAPCredentialStore
    private let transportFactory: IMAPTransportFactory
    private let limits: IMAPClient.Limits
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "imap")

    init(
        keychain: Keychain,
        transportFactory: @escaping IMAPTransportFactory = IMAPTransports.default,
        limits: IMAPClient.Limits = IMAPClient.Limits()
    ) {
        self.store = IMAPCredentialStore(keychain: keychain)
        self.transportFactory = transportFactory
        self.limits = limits
    }

    nonisolated func makeClient(_ settings: IMAPAccountSettings) -> IMAPClient {
        IMAPClient(endpoint: IMAPEndpoint(settings: settings), limits: limits, transportFactory: transportFactory)
    }

    // MARK: - Sign-in

    /// Collects the server settings and the password, proves they work, and parks them as a pending sign-in for
    /// `AccountLinker` to bind. Nothing is written to the Keychain until the mailbox actually opened read-only.
    @MainActor
    func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
        let credentials = try await IMAPSetupPresenter.present(from: presenting) { [self] candidate in
            await validateForUI(candidate)
        }
        let settings = credentials.settings.normalized
        let stored = IMAPCredentials(settings: settings, password: credentials.password)
        try store.storePending(IMAPPendingSignIn(credentials: stored, createdAt: .now))
        return SignedInIdentity(
            providerAccountID: "\(settings.host):\(settings.port)|\(settings.username.lowercased())",
            email: settings.email,
            displayName: settings.displayName
        )
    }

    /// Connects, authenticates and opens INBOX read-only. Throws the specific `IMAPError` on failure.
    nonisolated func validate(_ credentials: IMAPCredentials) async throws {
        let settings = credentials.settings.normalized
        if let problem = settings.validationProblem {
            throw IMAPError.invalidSettings(problem)
        }
        let client = makeClient(settings)
        do {
            try await client.connect()
            try await client.authenticate(username: settings.username, password: credentials.password)
            _ = try await client.examine()
        } catch {
            await client.disconnect()
            throw error
        }
        await client.disconnect()
    }

    /// `validate`, rendered for the setup screen.
    nonisolated func validateForUI(_ credentials: IMAPCredentials) async -> IMAPValidationOutcome {
        do {
            try await validate(credentials)
            return .success
        } catch let error as IMAPError {
            return .failure(error.errorDescription ?? "The mail server could not be reached.")
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    /// Moves the pending sign-in for `identity.email` under the account's own Keychain keys, replacing whatever
    /// was there (the "sign in again" path after a password change).
    func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws {
        guard let pending = try store.takePending(email: identity.email) else {
            logger.error("No pending IMAP sign-in to bind to account \(accountID.uuidString, privacy: .private)")
            throw ProviderError.notAuthenticated
        }
        guard pending.credentials.settings.email.caseInsensitiveCompare(identity.email) == .orderedSame else {
            logger.error("Pending IMAP sign-in does not match the identity being linked; discarded")
            throw ProviderError.notAuthenticated
        }
        try store.store(pending.credentials, for: accountID)
        logger.info("Bound the pending IMAP sign-in to account \(accountID.uuidString, privacy: .private)")
    }

    /// Forgets the password and the server settings. There is nothing to revoke server-side: IMAP has no token.
    func signOut(accountID: UUID) async throws {
        if let settings = try? store.settings(for: accountID) {
            try? store.deletePending(email: settings.email)
        }
        try store.delete(accountID: accountID)
        logger.info("IMAP account signed out")
    }

    // MARK: - Push

    /// IMAP has no webhook. `IMAP IDLE` needs a socket held open, which iOS will not allow in the background,
    /// so these accounts rely on foreground scans and background refresh.
    func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState {
        throw ProviderError.pushNotSupported
    }

    // MARK: - Fetch

    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
        try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback, isProcessed: { _ in false })
    }

    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        guard let credentials = try store.credentials(for: accountID) else {
            throw ProviderError.notAuthenticated
        }
        let settings = credentials.settings.normalized
        let client = makeClient(settings)
        do {
            let result = try await runFetch(
                accountID: accountID, settings: settings, password: credentials.password,
                cursor: cursor, lookback: lookback, isProcessed: isProcessed, client: client
            )
            await client.disconnect()
            return result
        } catch {
            await client.disconnect()
            throw Self.providerError(from: error)
        }
    }

    private func runFetch(
        accountID: UUID,
        settings: IMAPAccountSettings,
        password: String,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool,
        client: IMAPClient
    ) async throws -> FetchResult {
        try await client.connect()
        try await client.authenticate(username: settings.username, password: password)
        let status = try await client.examine()

        let stored = cursor.flatMap { IMAPSyncCursor(opaque: $0.opaque) }
        let isIncremental = stored?.uidValidity == status.uidValidity
        if let stored, !isIncremental {
            logger.notice("IMAP UIDVALIDITY changed (\(stored.uidValidity, privacy: .public) → \(status.uidValidity, privacy: .public)); the cursor was reset")
        }

        var candidates: [UInt32]
        if isIncremental, let stored {
            let searched = try await client.uidSearch(.uidFrom(stored.lastUID &+ 1))
            // "<n>:*" always matches at least the highest UID, even when it is below <n>.
            candidates = searched.filter { $0 > stored.lastUID }
        } else {
            let since = Date().addingTimeInterval(-max(lookback, 3600))
            candidates = try await client.uidSearch(.since(since))
        }
        candidates.sort()

        let uidValidity = status.uidValidity
        let highestSeen = candidates.last ?? stored?.lastUID ?? status.uidNext.map { $0 &- 1 } ?? 0

        // Skip-before-download: already-classified messages never reach a FETCH and do not use up the batch.
        let fresh = candidates.filter { !isProcessed(Self.messageID(uidValidity: uidValidity, uid: $0)) }

        var selected: [UInt32]
        var newLastUID: UInt32
        if fresh.count > Self.maxMessagesPerFetch {
            if isIncremental {
                // Oldest first: the cursor only advances over what was fetched, so the rest arrives next scan.
                selected = Array(fresh.prefix(Self.maxMessagesPerFetch))
                newLastUID = selected.last ?? stored?.lastUID ?? 0
                logger.warning("IMAP fetch hit the \(Self.maxMessagesPerFetch)-message cap; the remainder follows on the next scan")
            } else {
                // First sync of a busy mailbox: the newest mail matters, and the cursor skips the rest of the
                // lookback window so it is not re-listed on every scan.
                selected = Array(fresh.suffix(Self.maxMessagesPerFetch))
                newLastUID = highestSeen
                logger.warning("IMAP first sync hit the \(Self.maxMessagesPerFetch)-message cap; older mail in the lookback window was skipped")
            }
        } else {
            selected = fresh
            newLastUID = highestSeen
        }
        if let stored, isIncremental { newLastUID = max(newLastUID, stored.lastUID) }

        let messages = try await fetchMessages(
            uids: selected, uidValidity: uidValidity, accountID: accountID, client: client
        )
        logger.info("IMAP fetch: \(candidates.count) candidates, \(selected.count) selected, \(messages.count) parsed, reset=\(!isIncremental, privacy: .public)")
        return FetchResult(
            messages: messages,
            cursor: IMAPSyncCursor(uidValidity: uidValidity, lastUID: newLastUID).syncCursor,
            cursorWasReset: !isIncremental
        )
    }

    static func messageID(uidValidity: UInt32, uid: UInt32) -> String { "\(uidValidity).\(uid)" }

    /// Fetches metadata first, then bodies: small messages whole (`BODY.PEEK[]`), big ones as the header block
    /// plus their inline text parts, so attachment bytes never come down the wire.
    private func fetchMessages(
        uids: [UInt32],
        uidValidity: UInt32,
        accountID: UUID,
        client: IMAPClient
    ) async throws -> [EmailMessage] {
        guard !uids.isEmpty else { return [] }
        var messages: [EmailMessage] = []
        var downloaded = 0

        for chunk in uids.chunked(into: Self.metadataChunkSize) {
            try Task.checkCancellation()
            let metadata = try await client.uidFetch(uids: chunk, items: [.uid, .internalDate, .rfc822Size, .bodyStructure])
            let byUID = Dictionary(uniqueKeysWithValues: metadata.map { ($0.uid, $0) })

            let withinBudget = downloaded < Self.maxTotalDownloadBytes
            let small = withinBudget
                ? metadata.filter { ($0.size ?? (Self.maxWholeMessageBytes + 1)) <= Self.maxWholeMessageBytes }.map(\.uid)
                : []

            if !small.isEmpty {
                let whole = try await client.uidFetch(uids: small, items: [.uid, .peekWhole])
                for fetched in whole {
                    guard let raw = fetched.sections["BODY[]"], !raw.isEmpty else { continue }
                    downloaded += raw.count
                    let meta = byUID[fetched.uid]
                    do {
                        var message = try MIMEParser.parse(
                            rfc822: raw,
                            provider: .imap,
                            accountID: accountID.uuidString,
                            messageID: Self.messageID(uidValidity: uidValidity, uid: fetched.uid),
                            receivedAt: fetched.internalDate ?? meta?.internalDate ?? Date()
                        )
                        if message.attachments.isEmpty, let structure = meta?.bodyStructure {
                            message.attachments = structure.attachments
                        }
                        messages.append(message)
                    } catch {
                        logger.notice("Skipped an IMAP message that did not parse as RFC 822")
                    }
                }
            }

            let large = metadata.filter { fetched in !small.contains(fetched.uid) }
            for meta in large {
                try Task.checkCancellation()
                if let message = try await fetchLarge(meta: meta, uidValidity: uidValidity, accountID: accountID, client: client, downloaded: &downloaded) {
                    messages.append(message)
                }
            }
        }
        return messages
    }

    /// Header block plus (budget permitting) the first inline text/plain and text/html parts.
    private func fetchLarge(
        meta: IMAPClient.FetchedMessage,
        uidValidity: UInt32,
        accountID: UUID,
        client: IMAPClient,
        downloaded: inout Int
    ) async throws -> EmailMessage? {
        var items: [IMAPFetchItem] = [.uid, .peekHeader]
        let preferred = meta.bodyStructure?.preferredTextParts()
        var plainNumber: String?
        var htmlNumber: String?
        if downloaded < Self.maxTotalDownloadBytes {
            if let plain = preferred?.plain, plain.part.size <= Self.maxPartBytes {
                plainNumber = plain.number
                items.append(.peekPart(plain.number))
            }
            if let html = preferred?.html, html.part.size <= Self.maxPartBytes {
                htmlNumber = html.number
                items.append(.peekPart(html.number))
            }
        }

        let fetched = try await client.uidFetch(uids: [meta.uid], items: items)
        guard let response = fetched.first, let headerData = response.sections["BODY[HEADER]"] else { return nil }
        downloaded += response.sections.values.reduce(0) { $0 + $1.count }

        let headers: [EmailHeader]
        do {
            headers = try MIMEParser.parseHeaders(headerData)
        } catch {
            logger.notice("Skipped an IMAP message whose header block did not parse")
            return nil
        }
        var message = EmailMessage(
            provider: .imap,
            accountID: accountID.uuidString,
            messageID: Self.messageID(uidValidity: uidValidity, uid: meta.uid),
            receivedAt: meta.internalDate ?? response.internalDate ?? Date(),
            headers: headers
        )
        message.subject = MIMEParser.decodeEncodedWords(message.header("Subject") ?? "")
        message.from = message.header("From").flatMap { EmailAddress.parse(MIMEParser.decodeEncodedWords($0)).first }
        message.sender = message.header("Sender").flatMap { EmailAddress.parse(MIMEParser.decodeEncodedWords($0)).first }
        message.replyTo = EmailAddress.parse(MIMEParser.decodeEncodedWords(message.header("Reply-To") ?? ""))
        message.to = EmailAddress.parse(MIMEParser.decodeEncodedWords(message.header("To") ?? ""))
        message.attachments = meta.bodyStructure?.attachments ?? []

        if let plainNumber, let data = response.sections["BODY[\(plainNumber)]"], let part = preferred?.plain?.part {
            message.textBody = IMAPPartDecoder.decode(data, encoding: part.encoding, charset: part.charset)
        }
        if let htmlNumber, let data = response.sections["BODY[\(htmlNumber)]"], let part = preferred?.html?.part {
            message.htmlBody = IMAPPartDecoder.decode(data, encoding: part.encoding, charset: part.charset)
        }
        return message
    }

    // MARK: - Errors

    /// Maps the transport-level failures onto the `ProviderError` cases the scan coordinator understands:
    /// a rejected password must become `notAuthenticated` so the account is flagged for "Sign in again".
    static func providerError(from error: Error) -> Error {
        switch error {
        case let error as IMAPError:
            if error.isAuthenticationFailure { return ProviderError.notAuthenticated }
            return ProviderError.network(error.errorDescription ?? "IMAP error")
        case is CancellationError:
            return error
        default:
            return error
        }
    }
}

private extension Array {
    /// Splits into consecutive slices of at most `size` elements.
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map { Array(self[$0..<Swift.min($0 + size, count)]) }
    }
}
