import CryptoKit
import Foundation

/// Build-time configuration. Values are injected via Config/Secrets.xcconfig → project.yml `info.properties` →
/// Info.plist, and read here at launch. Placeholder values from Secrets.example.xcconfig are treated as unset.
struct AppConfig: Sendable, Equatable {
    var googleClientID: String?
    var googleReversedClientID: String?
    var gmailPubSubTopic: String?
    var microsoftClientID: String?
    var relayBaseURL: URL?
    var relayAPIKey: String?
    var relaySalt: String?
    var bundleIdentifier: String

    /// The configuration of the running app (reads `Bundle.main`).
    static let current = AppConfig(bundle: .main)

    init(
        googleClientID: String? = nil,
        googleReversedClientID: String? = nil,
        gmailPubSubTopic: String? = nil,
        microsoftClientID: String? = nil,
        relayBaseURL: URL? = nil,
        relayAPIKey: String? = nil,
        relaySalt: String? = nil,
        bundleIdentifier: String = "com.mazooni.PhishGuard"
    ) {
        self.googleClientID = googleClientID
        self.googleReversedClientID = googleReversedClientID
        self.gmailPubSubTopic = gmailPubSubTopic
        self.microsoftClientID = microsoftClientID
        self.relayBaseURL = relayBaseURL
        self.relayAPIKey = relayAPIKey
        self.relaySalt = relaySalt
        self.bundleIdentifier = bundleIdentifier
    }

    init(bundle: Bundle) {
        self.init(
            googleClientID: Self.value("GOOGLE_CLIENT_ID", in: bundle),
            googleReversedClientID: Self.value("GOOGLE_REVERSED_CLIENT_ID", in: bundle),
            gmailPubSubTopic: Self.value("GMAIL_PUBSUB_TOPIC", in: bundle),
            microsoftClientID: Self.value("MS_CLIENT_ID", in: bundle),
            relayBaseURL: Self.value("RELAY_BASE_URL", in: bundle).flatMap { URL(string: $0) },
            relayAPIKey: Self.value("RELAY_API_KEY", in: bundle),
            relaySalt: Self.value("RELAY_SALT", in: bundle),
            bundleIdentifier: bundle.bundleIdentifier ?? "com.mazooni.PhishGuard"
        )
    }

    // MARK: - Derived

    var isGoogleConfigured: Bool { googleClientID != nil && googleReversedClientID != nil }
    var isMicrosoftConfigured: Bool { microsoftClientID != nil }
    var isRelayConfigured: Bool { relayConfig != nil }

    /// Relay configuration, nil when RELAY_BASE_URL, RELAY_API_KEY or RELAY_SALT is unset or still a placeholder
    /// (the app then relies on Background App Refresh only). The salt is mandatory: the relay derives the Gmail
    /// `accountKey` from each Pub/Sub notification with its own RELAY_SALT, so a key hashed without the salt never
    /// matches and would also leak a dictionary-reversible hash of the address.
    var relayConfig: RelayConfig? {
        guard let relayBaseURL, let relayAPIKey, let relaySalt, !relaySalt.isEmpty else { return nil }
        return RelayConfig(baseURL: relayBaseURL, apiKey: relayAPIKey, gmailPubSubTopic: gmailPubSubTopic ?? "")
    }

    /// Relay keys that are unset or placeholders (empty when the relay is configured), for Diagnostics.
    var missingRelayKeys: [String] {
        var missing: [String] = []
        if relayBaseURL == nil { missing.append("RELAY_BASE_URL") }
        if relayAPIKey == nil { missing.append("RELAY_API_KEY") }
        if relaySalt?.isEmpty ?? true { missing.append("RELAY_SALT") }
        return missing
    }

    /// `accountKey = SHA256(lowercased(email) + ":" + relaySalt)` hex. The relay only ever sees this key, never the email.
    /// Only meaningful when `relayConfig` is non-nil (which guarantees a salt); every relay call site is gated on it.
    func accountKey(for email: String) -> String {
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let input = Data((normalized + ":" + (relaySalt ?? "")).utf8)
        return SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined()
    }

    var backgroundRefreshTaskIdentifier: String { bundleIdentifier + ".refresh" }
    var backgroundProcessingTaskIdentifier: String { bundleIdentifier + ".process" }

    // MARK: - APNs environment

    static let apnsSandbox = "sandbox"
    static let apnsProduction = "production"

    /// APNs environment reported to the relay (`"sandbox"` or `"production"`), so it can pick the matching APNs host.
    ///
    /// Detected from the `aps-environment` entry of the embedded provisioning profile (`development` ⇒ sandbox,
    /// `production` ⇒ production — TestFlight and App Store builds carry `production`). Falls back to the build
    /// configuration (DEBUG ⇒ sandbox) when there is no profile, e.g. on the simulator.
    var apnsEnvironment: String { Self.detectedAPNsEnvironment }

    /// Computed once per process from `Bundle.main`.
    static let detectedAPNsEnvironment: String = detectAPNsEnvironment(bundle: .main)

    static func detectAPNsEnvironment(bundle: Bundle) -> String {
        if let url = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
           let data = try? Data(contentsOf: url),
           let environment = apnsEnvironment(fromProvisioningProfile: data) {
            return environment
        }
        return fallbackAPNsEnvironment
    }

    /// DEBUG ⇒ sandbox, otherwise production.
    static var fallbackAPNsEnvironment: String {
        #if DEBUG
        return apnsSandbox
        #else
        return apnsProduction
        #endif
    }

    /// Parses `aps-environment` out of a provisioning profile (a CMS envelope whose plist payload is plain text).
    /// Returns `"sandbox"` for `development`, `"production"` for `production`, nil when the key is absent.
    static func apnsEnvironment(fromProvisioningProfile data: Data) -> String? {
        guard let text = String(data: data, encoding: .isoLatin1),
              let keyRange = text.range(of: "<key>aps-environment</key>") else { return nil }
        let remainder = text[keyRange.upperBound...]
        guard let open = remainder.range(of: "<string>"),
              let close = remainder[open.upperBound...].range(of: "</string>") else { return nil }
        let value = remainder[open.upperBound..<close.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch value {
        case "development": return apnsSandbox
        case "production": return apnsProduction
        default: return nil
        }
    }

    // MARK: - Info.plist reading

    private static func value(_ key: String, in bundle: Bundle) -> String? {
        guard let raw = bundle.object(forInfoDictionaryKey: key) as? String else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isPlaceholder(trimmed) else { return nil }
        return trimmed
    }

    /// True for the sample values shipped in Secrets.example.xcconfig and for unexpanded `$(...)` settings.
    static func isPlaceholder(_ value: String) -> Bool {
        let lower = value.lowercased()
        return lower.hasPrefix("$(")
            || lower.contains("replace-me")
            || lower.contains("example.com")
            || lower.contains("your-gcp-project")
            || lower.contains("1234567890-abcdefghijklmnop")
            || lower == "00000000-0000-0000-0000-000000000000"
    }
}
