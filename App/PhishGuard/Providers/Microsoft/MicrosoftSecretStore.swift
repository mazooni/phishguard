import Foundation
import PhishCore

/// The subset of `Keychain` the Microsoft provider needs. Abstracted so unit tests can substitute an
/// in-memory store; production always uses the app `Keychain`.
protocol MicrosoftSecretStore: Sendable {
    func getString(_ key: String) throws -> String?
    func setString(_ value: String, for key: String) throws
    func delete(_ key: String) throws
}

extension Keychain: MicrosoftSecretStore {}

/// Keychain keys owned by the Microsoft provider. Everything is scoped per `LinkedAccount.id`; the identity
/// returned by `signIn` is written by `linkAccount(accountID:identity:)`, never parked in a shared slot.
enum MicrosoftKeychainKeys {
    /// MSAL `MSALAccount.identifier` (used by `acquireTokenSilent`).
    static let accountIdentifierPrefix = "microsoft.accountIdentifier."
    /// The mailbox address returned by `/me` at sign-in (needed to derive the relay `accountKey`).
    static let emailPrefix = "microsoft.email."
    /// Random per-account webhook secret sent to Graph as `clientState` and registered with the relay.
    static let clientStatePrefix = "microsoft.clientState."
    /// The id of the Graph subscription created for the account, so `signOut` can delete it.
    static let subscriptionIDPrefix = "microsoft.subscriptionID."

    static func accountIdentifier(_ accountID: UUID) -> String { accountIdentifierPrefix + accountID.uuidString }
    static func email(_ accountID: UUID) -> String { emailPrefix + accountID.uuidString }
    static func clientState(_ accountID: UUID) -> String { clientStatePrefix + accountID.uuidString }
    static func subscriptionID(_ accountID: UUID) -> String { subscriptionIDPrefix + accountID.uuidString }
}

/// The relay calls the Microsoft provider makes. `RelayClient` is the production implementation; tests record calls.
protocol GraphRelayRegistrar: Sendable {
    func registerAccount(accountKey: String, provider: MailProvider) async throws
    func unregisterAccount(accountKey: String) async throws
    func registerGraphSubscription(subscriptionID: String, accountKey: String, clientState: String) async throws
}

extension RelayClient: GraphRelayRegistrar {}
