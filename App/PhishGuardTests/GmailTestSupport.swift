import Foundation
import Synchronization
import XCTest
@testable import PhishGuard

// Shared test plumbing for the Gmail provider: a URLProtocol-backed stub server and JSON fixtures.

/// A reference-typed lock box (`Mutex` itself is non-copyable, so it cannot be captured by value in closures).
final class GmailLocked<Value: Sendable>: Sendable {
    private let mutex: Mutex<Value>

    init(_ value: Value) {
        mutex = Mutex(value)
    }

    func withLock<Result: Sendable>(_ body: (inout Value) throws -> Result) rethrows -> Result {
        try mutex.withLock { value in try body(&value) }
    }

    var value: Value { withLock { $0 } }
}

/// Serves canned responses to a `URLSession` created by `makeSession()` and records every request it saw.
/// Handlers run on URLSession's queues, so everything here is `Sendable`.
final class GmailStubServer: Sendable {
    struct Request: Sendable {
        var method: String
        var url: URL
        var headers: [String: String]
        var body: Data?

        var path: String { url.path }
        var query: [String: String] {
            var result: [String: String] = [:]
            for item in URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? [] {
                result[item.name] = item.value ?? ""
            }
            return result
        }
        var jsonBody: [String: Any]? {
            body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        }
        var formBody: [String: String] {
            guard let body, let text = String(data: body, encoding: .utf8) else { return [:] }
            var result: [String: String] = [:]
            for pair in text.split(separator: "&") {
                let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
                result[parts[0]] = parts.count > 1 ? parts[1].removingPercentEncoding ?? parts[1] : ""
            }
            return result
        }
    }

    struct Response: Sendable {
        var status: Int
        var body: Data
        var headers: [String: String] = [:]

        static func json(_ object: Any, status: Int = 200, headers: [String: String] = [:]) -> Response {
            Response(status: status, body: GmailFixtures.data(object), headers: headers.merging(["Content-Type": "application/json"]) { first, _ in first })
        }

        static func googleError(status: Int, reason: String, message: String = "error", headers: [String: String] = [:]) -> Response {
            json(
                ["error": ["code": status, "message": message, "status": "ERROR", "errors": [["domain": "global", "reason": reason, "message": message]]]],
                status: status,
                headers: headers
            )
        }

        static let notFound = googleError(status: 404, reason: "notFound", message: "Requested entity was not found.")
        static let empty = Response(status: 204, body: Data())
    }

    typealias Handler = @Sendable (Request) -> Response

    let id = UUID().uuidString
    private let handler = Mutex<Handler?>(nil)
    private let recorded = Mutex<[Request]>([])

    /// Installs the request handler (replacing any previous one).
    func handle(_ handler: @escaping Handler) {
        self.handler.withLock { $0 = handler }
    }

    var requests: [Request] { recorded.withLock { $0 } }

    func requests(matching path: String) -> [Request] { requests.filter { $0.path == path } }

    func respond(to request: Request) -> Response {
        recorded.withLock { $0.append(request) }
        let handler = handler.withLock { $0 }
        return handler?(request) ?? .notFound
    }

    /// A session whose every request is answered by this server. The session tags its requests with an id header;
    /// the most recently created server is also the fallback so nothing ever reaches the network.
    func makeSession() -> URLSession {
        GmailStubURLProtocol.registry.withLock { $0[id] = self }
        GmailStubURLProtocol.current.withLock { $0 = self }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [GmailStubURLProtocol.self]
        configuration.httpAdditionalHeaders = [GmailStubURLProtocol.serverHeader: id]
        return URLSession(configuration: configuration)
    }
}

final class GmailStubURLProtocol: URLProtocol {
    static let serverHeader = "X-PhishGuard-Stub-Server"
    static let registry = Mutex<[String: GmailStubServer]>([:])
    static let current = Mutex<GmailStubServer?>(nil)

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let tagged = request.value(forHTTPHeaderField: Self.serverHeader).flatMap { id in Self.registry.withLock { $0[id] } }
        guard let url = request.url, let server = tagged ?? Self.current.withLock({ $0 }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        var headers: [String: String] = [:]
        for (name, value) in request.allHTTPHeaderFields ?? [:] where name != Self.serverHeader {
            headers[name] = value
        }
        let recorded = GmailStubServer.Request(method: request.httpMethod ?? "GET", url: url, headers: headers, body: Self.body(of: request))
        let response = server.respond(to: recorded)
        guard let http = HTTPURLResponse(url: url, statusCode: response.status, httpVersion: "HTTP/1.1", headerFields: response.headers) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: response.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    /// URLSession hands bodies to protocols as a stream; read it back.
    private static func body(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: bufferSize)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// Builders for Gmail JSON payloads (`[String: Any]` trees serialized with `data(_:)`).
enum GmailFixtures {
    static let gmailPath = "/gmail/v1/users/me"

    static func data(_ object: Any) -> Data {
        // swiftlint:disable:next force_try
        try! JSONSerialization.data(withJSONObject: object)
    }

    /// Gmail's base64url alphabet without padding.
    static func base64URL(_ text: String) -> String {
        base64URL(Data(text.utf8))
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func header(_ name: String, _ value: String) -> [String: Any] {
        ["name": name, "value": value]
    }

    static func part(
        mimeType: String,
        text: String? = nil,
        rawData: String? = nil,
        filename: String? = nil,
        headers: [[String: Any]] = [],
        attachmentId: String? = nil,
        size: Int? = nil,
        parts: [[String: Any]]? = nil
    ) -> [String: Any] {
        var part: [String: Any] = ["mimeType": mimeType, "partId": UUID().uuidString]
        var body: [String: Any] = [:]
        if let rawData {
            body["data"] = rawData
        } else if let text {
            body["data"] = base64URL(text)
        }
        if let attachmentId { body["attachmentId"] = attachmentId }
        if let size {
            body["size"] = size
        } else if let text {
            body["size"] = text.utf8.count
        }
        part["body"] = body
        if let filename { part["filename"] = filename }
        if !headers.isEmpty { part["headers"] = headers }
        if let parts { part["parts"] = parts }
        return part
    }

    static func multipart(_ mimeType: String, parts: [[String: Any]], headers: [[String: Any]] = []) -> [String: Any] {
        var container: [String: Any] = ["mimeType": mimeType, "partId": UUID().uuidString, "body": ["size": 0], "parts": parts]
        if !headers.isEmpty { container["headers"] = headers }
        return container
    }

    static func message(
        id: String,
        threadId: String? = "thread-1",
        internalDate: Int64? = 1_700_000_000_000,
        labelIds: [String] = ["INBOX", "UNREAD"],
        headers: [[String: Any]],
        payload: [String: Any]
    ) -> [String: Any] {
        var message: [String: Any] = ["id": id, "labelIds": labelIds, "historyId": "12345", "sizeEstimate": 1024]
        var payload = payload
        payload["headers"] = headers
        message["payload"] = payload
        if let threadId { message["threadId"] = threadId }
        if let internalDate { message["internalDate"] = String(internalDate) }
        return message
    }

    static func standardHeaders(
        from: String = "Alice <alice@example.com>",
        to: String = "Bob <bob@example.org>",
        subject: String = "Hello",
        messageID: String? = "<abc123@mail.example.com>",
        date: String = "Tue, 14 Nov 2023 22:13:20 +0000",
        extra: [[String: Any]] = []
    ) -> [[String: Any]] {
        var headers = [header("From", from), header("To", to), header("Subject", subject), header("Date", date)]
        if let messageID { headers.append(header("Message-ID", messageID)) }
        headers.append(contentsOf: extra)
        return headers
    }

    /// A ready-to-serve `messages.get?format=full` document with a plain-text body.
    static func plainMessage(id: String, internalDate: Int64, subject: String = "Hello", text: String = "Body", messageID: String? = nil) -> [String: Any] {
        message(
            id: id,
            internalDate: internalDate,
            headers: standardHeaders(subject: subject, messageID: messageID ?? "<\(id)@mail.example.com>"),
            payload: part(mimeType: "text/plain", text: text)
        )
    }

    static func historyPage(records: [(id: String, messages: [(id: String, labels: [String])])], historyId: String, nextPageToken: String? = nil) -> [String: Any] {
        var page: [String: Any] = ["historyId": historyId]
        page["history"] = records.map { record -> [String: Any] in
            [
                "id": record.id,
                "messagesAdded": record.messages.map { ["message": ["id": $0.id, "threadId": "t-\($0.id)", "labelIds": $0.labels]] },
            ]
        }
        if let nextPageToken { page["nextPageToken"] = nextPageToken }
        return page
    }

    static func listPage(ids: [String], nextPageToken: String? = nil) -> [String: Any] {
        var page: [String: Any] = ["messages": ids.map { ["id": $0, "threadId": "t-\($0)"] }, "resultSizeEstimate": ids.count]
        if let nextPageToken { page["nextPageToken"] = nextPageToken }
        return page
    }

    static func profile(email: String = "user@example.com", historyId: String) -> [String: Any] {
        ["emailAddress": email, "messagesTotal": 42, "threadsTotal": 40, "historyId": historyId]
    }
}

// MARK: - Assertions

/// Runs `body` and hands the thrown error to `check`; fails when nothing was thrown or `check` returns false.
/// Inherits the caller's isolation so main-actor tests can pass non-Sendable closures.
func assertThrowsProviderError(
    _ description: String,
    isolation: isolated (any Actor)? = #isolation,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ check: (ProviderError) -> Bool,
    _ body: () async throws -> Void
) async {
    do {
        try await body()
        XCTFail("Expected \(description) to be thrown", file: file, line: line)
    } catch let error as ProviderError {
        XCTAssertTrue(check(error), "Expected \(description), got \(error)", file: file, line: line)
    } catch {
        XCTFail("Expected \(description), got \(error)", file: file, line: line)
    }
}
