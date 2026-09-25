import Foundation

/// Everything the IMAP client can fail with. The messages are user-facing: `IMAPSetupView` shows
/// `errorDescription` verbatim under "Test connection", so each case names the thing the user can fix.
///
/// Server text is included only where the server is expected to explain itself (a tagged `NO`/`BAD`). It is
/// never logged — `IMAPClient` logs the case, not the message, because a server may echo the address back.
enum IMAPError: Error, LocalizedError, Equatable, Sendable {
    /// The host name does not resolve.
    case hostNotFound(String)
    /// TCP connect / TLS handshake failed, or the connection dropped while connecting.
    case connectionFailed(String)
    /// The TLS handshake itself failed (bad certificate, wrong port, plaintext server).
    case tlsFailed(String)
    /// The server advertises no STARTTLS and the account is configured for it.
    case startTLSUnavailable
    /// Nothing arrived within the command timeout.
    case timedOut
    /// The server closed the connection (or `* BYE`) while a command was in flight.
    case connectionClosed
    /// The response does not parse as IMAP.
    case protocolViolation(String)
    /// A response (or a single literal) exceeded the hard cap.
    case responseTooLarge(limit: Int)
    /// LOGIN/AUTHENTICATE was refused.
    case authenticationFailed(serverMessage: String?)
    /// The server told us a normal password is not accepted for mail apps.
    case appPasswordRequired(serverMessage: String?)
    /// A tagged NO/BAD for something other than authentication.
    case commandFailed(command: String, serverMessage: String?)
    /// `EXAMINE` came back without `[READ-ONLY]`: refuse to keep going rather than risk a writable session.
    case mailboxNotReadOnly
    /// A command outside the read-only allow-list was about to be written. Unreachable by construction
    /// (`IMAPCommand` cannot express a mutating command); kept as a belt-and-braces guard with a test.
    case forbiddenCommand(String)
    /// The mailbox does not exist (INBOX should always exist, so this means the account is unusual).
    case mailboxNotFound(String)
    /// The details the user typed are not usable yet; the message names what to fix. Nothing is connected to.
    case invalidSettings(String)

    var errorDescription: String? {
        switch self {
        case .hostNotFound(let host):
            return "Could not find the mail server “\(host)”. Check the server address."
        case .connectionFailed(let detail):
            return "Could not reach the mail server (\(detail)). Check the address, the port and your connection."
        case .tlsFailed(let detail):
            return "The secure connection to the mail server failed (\(detail)). Check the port and the encryption setting."
        case .startTLSUnavailable:
            return "This server does not offer STARTTLS on this port. Try SSL/TLS on port 993."
        case .timedOut:
            return "The mail server did not answer in time."
        case .connectionClosed:
            return "The mail server closed the connection."
        case .protocolViolation(let detail):
            return "The server sent something PhishGuard could not read (\(detail))."
        case .responseTooLarge(let limit):
            return "The server sent more than \(limit / 1_048_576) MB in one response; PhishGuard stopped reading."
        case .authenticationFailed(let message):
            let detail = Self.trimmedServerMessage(message)
            return "The mail server rejected the email address or password.\(detail.map { " The server said: \($0)" } ?? "")"
        case .appPasswordRequired(let message):
            let detail = Self.trimmedServerMessage(message)
            return "This account needs an app-specific password instead of your normal password.\(detail.map { " The server said: \($0)" } ?? "")"
        case .commandFailed(let command, let message):
            let detail = Self.trimmedServerMessage(message)
            return "The mail server refused \(command).\(detail.map { " It said: \($0)" } ?? "")"
        case .mailboxNotReadOnly:
            return "The server did not open the mailbox read-only, so PhishGuard stopped. Nothing was changed."
        case .forbiddenCommand(let verb):
            return "PhishGuard blocked the command \(verb) because it is not read-only."
        case .mailboxNotFound(let mailbox):
            return "The mailbox “\(mailbox)” does not exist on this server."
        case .invalidSettings(let problem):
            return problem
        }
    }

    /// True when re-entering the password is the fix — the caller flags the account for re-authentication.
    var isAuthenticationFailure: Bool {
        switch self {
        case .authenticationFailed, .appPasswordRequired: return true
        default: return false
        }
    }

    /// Server text, trimmed and capped. Response codes such as `[AUTHENTICATIONFAILED]` are kept: they are the
    /// most specific thing many servers say.
    private static func trimmedServerMessage(_ message: String?) -> String? {
        guard let message else { return nil }
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return trimmed.count > 160 ? String(trimmed.prefix(160)) + "…" : trimmed
    }

    /// Maps a tagged `NO`/`BAD` for a login command onto the specific failure, using the response code and the
    /// wording providers actually send ("Application-specific password required", "[AUTHENTICATIONFAILED]").
    static func loginFailure(code: String?, message: String?) -> IMAPError {
        let haystack = ((code ?? "") + " " + (message ?? "")).lowercased()
        let appPasswordHints = [
            "application-specific password",
            "app-specific password",
            "app password",
            "apppassword",
            "webalert",
            "authenticate with an app",
        ]
        if appPasswordHints.contains(where: { haystack.contains($0) }) {
            return .appPasswordRequired(serverMessage: message)
        }
        return .authenticationFailed(serverMessage: message)
    }
}
