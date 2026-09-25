import Foundation
import OSLog

/// Graph change-notification subscriptions on `me/mailFolders('Inbox')/messages` that ring the relay webhook.
struct GraphSubscriptionManager: Sendable {
    /// Outlook `message` subscriptions may live at most 10,080 minutes (< 7 days) — research §3.
    static let maxLifetime: TimeInterval = 10_080 * 60
    /// Requested lifetime stays one hour under the maximum so clock skew never trips Graph's limit.
    static let safetyMargin: TimeInterval = 3600
    static let requestedLifetime: TimeInterval = maxLifetime - safetyMargin
    static let resource = "me/mailFolders('Inbox')/messages"
    static let changeType = "created"
    static let notificationPath = "v1/graph/notifications"
    /// Lifecycle events (`subscriptionRemoved`, `missed`, `reauthorizationRequired`) — the relay forwards them to the
    /// device as a silent push with `lifecycleEvent`. Must be set at creation (research §3).
    static let lifecyclePath = "v1/graph/lifecycle"
    static let subscriptionsPath = "subscriptions"
    /// Graph caps `clientState` at 128 characters; 32 random bytes hex-encoded is 64.
    static let clientStateByteCount = 32

    struct Created: Sendable, Equatable {
        var id: String
        var expiresAt: Date
    }

    var client: GraphClient
    var now: @Sendable () -> Date

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "microsoft.subscription")

    init(client: GraphClient, now: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.now = now
    }

    // MARK: - Pure helpers (unit tested)

    static func notificationURL(relayBaseURL: URL) -> URL {
        relayBaseURL.appending(path: notificationPath)
    }

    static func lifecycleURL(relayBaseURL: URL) -> URL {
        relayBaseURL.appending(path: lifecyclePath)
    }

    static func expiration(from now: Date) -> Date {
        now.addingTimeInterval(requestedLifetime)
    }

    static func clientState(randomBytes: [UInt8]) -> String {
        randomBytes.map { String(format: "%02x", $0) }.joined()
    }

    static func createBody(notificationURL: URL, lifecycleURL: URL, clientState: String, expiration: Date) throws -> Data {
        let body: [String: String] = [
            "changeType": changeType,
            "notificationUrl": notificationURL.absoluteString,
            "lifecycleNotificationUrl": lifecycleURL.absoluteString,
            "resource": resource,
            "expirationDateTime": GraphDate.string(from: expiration),
            "clientState": clientState,
        ]
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    }

    static func renewBody(expiration: Date) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["expirationDateTime": GraphDate.string(from: expiration)], options: [.sortedKeys])
    }

    // MARK: - Graph calls

    /// `POST /subscriptions`. Throws `GraphError` (409 when an equivalent subscription already exists).
    func create(token: String, notificationURL: URL, lifecycleURL: URL, clientState: String) async throws -> Created {
        let requested = Self.expiration(from: now())
        let body = try Self.createBody(notificationURL: notificationURL, lifecycleURL: lifecycleURL, clientState: clientState, expiration: requested)
        let response = try await client.request(
            GraphClient.url(for: Self.subscriptionsPath),
            method: "POST",
            token: token,
            prefer: [GraphClient.immutableIDPreference],
            body: body
        )
        let subscription = try client.decode(GraphSubscription.self, from: response.data)
        guard let id = subscription.id, !id.isEmpty else { throw ProviderError.decoding("Graph subscription response has no id") }
        let expiresAt = subscription.expirationDateTime.flatMap(GraphDate.parse) ?? requested
        logger.info("Created Graph subscription expiring \(expiresAt.description, privacy: .public)")
        return Created(id: id, expiresAt: expiresAt)
    }

    /// `PATCH /subscriptions/{id}`. Throws `GraphError(status: 404)` when the subscription no longer exists.
    func renew(id: String, token: String) async throws -> Date {
        let requested = Self.expiration(from: now())
        let response = try await client.request(
            GraphClient.url(for: "\(Self.subscriptionsPath)/\(id)"),
            method: "PATCH",
            token: token,
            body: try Self.renewBody(expiration: requested)
        )
        let subscription = try? client.decode(GraphSubscription.self, from: response.data)
        let expiresAt = subscription?.expirationDateTime.flatMap(GraphDate.parse) ?? requested
        logger.info("Renewed Graph subscription until \(expiresAt.description, privacy: .public)")
        return expiresAt
    }

    /// `DELETE /subscriptions/{id}`; a 404 counts as success.
    func delete(id: String, token: String) async throws {
        do {
            _ = try await client.request(GraphClient.url(for: "\(Self.subscriptionsPath)/\(id)"), method: "DELETE", token: token)
        } catch let error as GraphError where error.status == 404 {
            return
        }
    }

    /// `GET /subscriptions` — the app's subscriptions for this user.
    func list(token: String) async throws -> [GraphSubscription] {
        let page: GraphCollectionPage<GraphSubscription> = try await client.get(Self.subscriptionsPath, token: token)
        return page.value
    }

    /// Removes subscriptions that point at `notificationURL` for the inbox resource (the cause of a 409 on create).
    func deleteConflicting(notificationURL: URL, token: String) async throws {
        let target = notificationURL.absoluteString.lowercased()
        for subscription in try await list(token: token) {
            guard let id = subscription.id,
                  subscription.notificationUrl?.lowercased() == target,
                  subscription.resource?.lowercased().contains("messages") == true
            else { continue }
            logger.notice("Deleting conflicting Graph subscription")
            try await delete(id: id, token: token)
        }
    }
}
