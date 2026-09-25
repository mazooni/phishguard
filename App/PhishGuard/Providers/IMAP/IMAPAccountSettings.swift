import Foundation

/// How the client secures the connection.
enum IMAPSecurity: String, Codable, Sendable, CaseIterable, Hashable {
    /// Implicit TLS from the first byte (port 993). What every preset uses.
    case tls
    /// Plaintext connect, then `STARTTLS` before `LOGIN` (port 143).
    case startTLS
    /// No encryption. Never offered in the UI; it exists so the tests can drive a loopback server.
    case none

    /// The options the setup screen offers. `.none` is deliberately absent.
    static var userSelectable: [IMAPSecurity] { [.tls, .startTLS] }

    var displayName: String {
        switch self {
        case .tls: return "SSL/TLS"
        case .startTLS: return "STARTTLS"
        case .none: return "None (insecure)"
        }
    }

    var defaultPort: Int {
        switch self {
        case .tls: return 993
        case .startTLS, .none: return 143
        }
    }
}

/// Everything needed to reach a mailbox, minus the password (which is stored under its own Keychain key so it
/// is never read back by anything that only wants the host or the address).
struct IMAPAccountSettings: Codable, Sendable, Equatable, Hashable {
    var host: String
    var port: Int
    var security: IMAPSecurity
    /// What the server wants for `LOGIN` — for every preset this is the full email address.
    var username: String
    /// The mailbox address shown in the app and used for the relay account key.
    var email: String
    var displayName: String?

    init(host: String, port: Int, security: IMAPSecurity, username: String, email: String, displayName: String? = nil) {
        self.host = host
        self.port = port
        self.security = security
        self.username = username
        self.email = email
        self.displayName = displayName
    }

    /// Trims whitespace, lowercases the host and the address, and drops an empty display name.
    var normalized: IMAPAccountSettings {
        var copy = self
        copy.host = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        copy.email = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        copy.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if copy.username.isEmpty { copy.username = copy.email }
        let name = displayName?.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.displayName = (name?.isEmpty ?? true) ? nil : name
        return copy
    }

    /// nil when the settings are usable, otherwise the first thing the user has to fix.
    var validationProblem: String? {
        let settings = normalized
        guard settings.email.contains("@"), settings.email.split(separator: "@").count == 2,
              !settings.email.hasPrefix("@"), !settings.email.hasSuffix("@") else {
            return "Enter the full email address."
        }
        guard !settings.host.isEmpty, settings.host.contains("."), !settings.host.contains(" ") else {
            return "Enter the IMAP server address, for example imap.example.com."
        }
        guard (1...65_535).contains(settings.port) else { return "The port must be between 1 and 65535." }
        return nil
    }
}

/// A known provider's IMAP endpoint.
struct IMAPServerPreset: Sendable, Equatable, Hashable {
    var name: String
    var host: String
    var port: Int
    var security: IMAPSecurity
    /// Address domains that map onto this preset.
    var domains: [String]
    /// Shown under the password field when the provider does not accept the account password.
    var passwordHint: String?
}

/// Auto-fill table for the common providers, plus a conservative `imap.<domain>` guess for everything else.
/// Every entry is implicit TLS on 993: no mainstream provider still wants plaintext 143.
enum IMAPServerDirectory {
    static let presets: [IMAPServerPreset] = [
        IMAPServerPreset(
            name: "iCloud Mail", host: "imap.mail.me.com", port: 993, security: .tls,
            domains: ["icloud.com", "me.com", "mac.com"],
            passwordHint: "iCloud needs an app-specific password from appleid.apple.com, not your Apple Account password."
        ),
        IMAPServerPreset(
            name: "Yahoo Mail", host: "imap.mail.yahoo.com", port: 993, security: .tls,
            domains: ["yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.ca", "yahoo.com.au", "yahoo.de",
                      "yahoo.fr", "yahoo.it", "yahoo.es", "ymail.com", "rocketmail.com"],
            passwordHint: "Yahoo needs an app password generated in your Yahoo account security settings."
        ),
        IMAPServerPreset(
            name: "Fastmail", host: "imap.fastmail.com", port: 993, security: .tls,
            domains: ["fastmail.com", "fastmail.fm", "fastmail.co.uk", "sent.com", "messagingengine.com"],
            passwordHint: "Fastmail needs an app password with IMAP access from Settings → Privacy & Security."
        ),
        IMAPServerPreset(
            name: "AOL Mail", host: "imap.aol.com", port: 993, security: .tls,
            domains: ["aol.com", "aim.com", "love.com", "games.com"],
            passwordHint: "AOL needs an app password generated in your AOL account security settings."
        ),
        IMAPServerPreset(
            name: "GMX", host: "imap.gmx.com", port: 993, security: .tls,
            domains: ["gmx.com", "gmx.us"],
            passwordHint: "Turn IMAP on in GMX under Settings → POP3 & IMAP first."
        ),
        IMAPServerPreset(
            name: "GMX (Germany)", host: "imap.gmx.net", port: 993, security: .tls,
            domains: ["gmx.net", "gmx.de", "gmx.at", "gmx.ch", "gmx.eu"],
            passwordHint: "Turn IMAP on in GMX under Settings → POP3 & IMAP first."
        ),
        IMAPServerPreset(
            name: "Zoho Mail", host: "imap.zoho.com", port: 993, security: .tls,
            domains: ["zoho.com", "zohomail.com"],
            passwordHint: "Zoho needs an application-specific password from Settings → Security."
        ),
        IMAPServerPreset(
            name: "Zoho Mail (EU)", host: "imap.zoho.eu", port: 993, security: .tls,
            domains: ["zoho.eu", "zohomail.eu"],
            passwordHint: "Zoho needs an application-specific password from Settings → Security."
        ),
        IMAPServerPreset(
            name: "Outlook.com", host: "outlook.office365.com", port: 993, security: .tls,
            domains: ["outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "live.co.uk", "msn.com", "passport.com"],
            passwordHint: "Microsoft accounts usually need the “Add Outlook / Hotmail” button instead — IMAP only works here when the account still allows an app password."
        ),
    ]

    /// The address domain, lowercased, or nil when the address has no `@`.
    static func domain(ofEmail email: String) -> String? {
        let parts = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().split(separator: "@")
        guard parts.count == 2, !parts[1].isEmpty else { return nil }
        return String(parts[1])
    }

    /// The preset whose domain list contains the address domain.
    static func preset(forEmail email: String) -> IMAPServerPreset? {
        guard let domain = domain(ofEmail: email) else { return nil }
        return presets.first { $0.domains.contains(domain) }
    }

    /// Server settings to pre-fill for an address: the preset when the domain is known, otherwise the usual
    /// `imap.<domain>` on 993, which is right for most hosted domains and is editable either way.
    static func suggestedSettings(forEmail email: String, displayName: String? = nil) -> IMAPAccountSettings? {
        let address = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let domain = domain(ofEmail: address) else { return nil }
        if let preset = preset(forEmail: address) {
            return IMAPAccountSettings(
                host: preset.host, port: preset.port, security: preset.security,
                username: address, email: address, displayName: displayName
            )
        }
        return IMAPAccountSettings(
            host: "imap." + domain, port: 993, security: .tls,
            username: address, email: address, displayName: displayName
        )
    }
}
