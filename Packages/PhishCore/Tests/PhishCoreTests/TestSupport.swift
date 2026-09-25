import Foundation
@testable import PhishCore

/// Builds synthetic emails for rule-level tests.
enum TestEmailFactory {
    static func email(
        from: EmailAddress? = EmailAddress(name: "Acme Notifications", address: "notify@acme-example.com"),
        sender: EmailAddress? = nil,
        replyTo: [EmailAddress] = [],
        to: [EmailAddress] = [EmailAddress(name: "Sam Rivera", address: "sam.rivera@example.com")],
        subject: String = "Hello",
        textBody: String? = "Hi Sam, just a note.",
        htmlBody: String? = nil,
        authenticationResults: String? = nil,
        extraHeaders: [EmailHeader] = [],
        attachments: [EmailAttachment] = []
    ) -> EmailMessage {
        var headers: [EmailHeader] = []
        if let from { headers.append(EmailHeader(name: "From", value: from.name.map { "\($0) <\(from.address)>" } ?? from.address)) }
        for r in replyTo { headers.append(EmailHeader(name: "Reply-To", value: r.address)) }
        headers.append(EmailHeader(name: "Subject", value: subject))
        if let authenticationResults { headers.append(EmailHeader(name: "Authentication-Results", value: authenticationResults)) }
        headers.append(contentsOf: extraHeaders)
        return EmailMessage(
            provider: .gmail,
            accountID: "test-account",
            messageID: UUID().uuidString,
            receivedAt: Date(timeIntervalSince1970: 1_789_990_200),
            from: from,
            sender: sender,
            replyTo: replyTo,
            to: to,
            subject: subject,
            textBody: textBody,
            htmlBody: htmlBody,
            headers: headers,
            attachments: attachments
        )
    }

    /// A fully authenticated, aligned sender ("clean" baseline).
    static let cleanAuth = "mx.example.com; dkim=pass header.d=acme-example.com header.s=s1 header.b=abc; spf=pass smtp.mailfrom=bounce@acme-example.com; dmarc=pass header.from=acme-example.com"
}

extension HeuristicReport {
    func has(_ id: String) -> Bool { signals.contains { $0.id == id } }
    func signal(_ id: String) -> Signal? { signals.first { $0.id == id } }
    var ids: [String] { signals.map(\.id) }
}
