import XCTest
@testable import PhishGuard

final class AppConfigTests: XCTestCase {
    /// A provisioning profile is a CMS envelope: binary bytes around a plain-text plist. Mimic that shape.
    private func profile(apsEnvironment: String?) -> Data {
        var plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>AppIDName</key>
            <string>PhishGuard</string>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>TEAMID.com.mazooni.PhishGuard</string>

        """
        if let apsEnvironment {
            plist += """
                    <key>aps-environment</key>
                    <string>\(apsEnvironment)</string>

            """
        }
        plist += """
                <key>get-task-allow</key>
                <true/>
            </dict>
        </dict>
        </plist>
        """
        var data = Data([0x30, 0x82, 0x1c, 0x00, 0x06, 0x09, 0x2a, 0x86, 0xff, 0xfe, 0x00])
        data.append(Data(plist.utf8))
        data.append(Data([0x00, 0xff, 0x80, 0x30, 0x82]))
        return data
    }

    func testAPNsEnvironmentParsedFromProvisioningProfile() {
        XCTAssertEqual(AppConfig.apnsEnvironment(fromProvisioningProfile: profile(apsEnvironment: "development")), "sandbox")
        XCTAssertEqual(AppConfig.apnsEnvironment(fromProvisioningProfile: profile(apsEnvironment: "production")), "production")
        XCTAssertEqual(AppConfig.apnsEnvironment(fromProvisioningProfile: profile(apsEnvironment: " Production ")), "production")
        XCTAssertNil(AppConfig.apnsEnvironment(fromProvisioningProfile: profile(apsEnvironment: "staging")))
        XCTAssertNil(AppConfig.apnsEnvironment(fromProvisioningProfile: profile(apsEnvironment: nil)))
        XCTAssertNil(AppConfig.apnsEnvironment(fromProvisioningProfile: Data()))
        XCTAssertNil(AppConfig.apnsEnvironment(fromProvisioningProfile: Data("<key>aps-environment</key><integer>1</integer>".utf8)))
    }

    func testAPNsEnvironmentFallsBackToBuildConfiguration() {
        // The test bundle carries no embedded.mobileprovision.
        let detected = AppConfig.detectAPNsEnvironment(bundle: Bundle(for: AppConfigTests.self))
        XCTAssertEqual(detected, AppConfig.fallbackAPNsEnvironment)
        #if DEBUG
        XCTAssertEqual(AppConfig.fallbackAPNsEnvironment, "sandbox")
        #else
        XCTAssertEqual(AppConfig.fallbackAPNsEnvironment, "production")
        #endif
        XCTAssertTrue(["sandbox", "production"].contains(AppConfig().apnsEnvironment))
        XCTAssertEqual(AppConfig().apnsEnvironment, AppConfig.detectedAPNsEnvironment)
    }

    func testBackgroundTaskIdentifiersDeriveFromBundle() {
        let config = AppConfig(bundleIdentifier: "com.example.app")
        XCTAssertEqual(config.backgroundRefreshTaskIdentifier, "com.example.app.refresh")
        XCTAssertEqual(config.backgroundProcessingTaskIdentifier, "com.example.app.process")
    }

    func testRelayConfigRequiresURLKeyAndSalt() {
        let url = URL(string: "https://relay.fly.dev")!
        XCTAssertNil(AppConfig(relayBaseURL: url, relaySalt: "s").relayConfig)
        XCTAssertNil(AppConfig(relayAPIKey: "k", relaySalt: "s").relayConfig)
        // URL + key without the salt: the relay derives Gmail account keys with its own salt, so an unsalted key
        // could never match; the relay must count as not configured rather than register unmatched keys.
        let unsalted = AppConfig(relayBaseURL: url, relayAPIKey: "k")
        XCTAssertNil(unsalted.relayConfig)
        XCTAssertFalse(unsalted.isRelayConfigured)
        XCTAssertEqual(unsalted.missingRelayKeys, ["RELAY_SALT"])
        XCTAssertNil(AppConfig(relayBaseURL: url, relayAPIKey: "k", relaySalt: "").relayConfig)
        XCTAssertEqual(AppConfig().missingRelayKeys, ["RELAY_BASE_URL", "RELAY_API_KEY", "RELAY_SALT"])

        let config = AppConfig(gmailPubSubTopic: "projects/p/topics/t", relayBaseURL: url, relayAPIKey: "k", relaySalt: "s")
        XCTAssertEqual(config.relayConfig, RelayConfig(baseURL: url, apiKey: "k", gmailPubSubTopic: "projects/p/topics/t"))
        XCTAssertTrue(config.isRelayConfigured)
        XCTAssertTrue(config.missingRelayKeys.isEmpty)
        XCTAssertNotEqual(config.accountKey(for: "a@b.example"), unsalted.accountKey(for: "a@b.example"), "the salt is part of the key")
    }
}
