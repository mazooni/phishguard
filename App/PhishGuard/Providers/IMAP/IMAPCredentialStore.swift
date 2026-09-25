import Foundation

/// Server settings plus the password that goes with them. Only ever held in memory while a connection is being
/// made, and in the Keychain otherwise.
struct IMAPCredentials: Codable, Sendable, Equatable {
    var settings: IMAPAccountSettings
    var password: String
}

/// A validated sign-in waiting to be bound to a `LinkedAccount` id by `AccountLinker`.
struct IMAPPendingSignIn: Codable, Sendable {
    var credentials: IMAPCredentials
    var createdAt: Date
}

/// Keychain layout for IMAP accounts. The password lives under its own key so code that only needs the host or
/// the address never reads it back (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, set by `Keychain`).
struct IMAPCredentialStore: Sendable {
    static let settingsKeyPrefix = "imap.settings."
    static let passwordKeyPrefix = "imap.password."
    /// Pending sign-ins are keyed by address, so two sign-ins in a row cannot overwrite each other.
    static let pendingKeyPrefix = "imap.pendingSignIn."
    /// A pending sign-in that was never bound (the app died between `signIn` and `linkAccount`) is discarded.
    static let pendingLifetime: TimeInterval = 3600

    let keychain: Keychain

    init(keychain: Keychain) {
        self.keychain = keychain
    }

    static func pendingKey(for email: String) -> String {
        pendingKeyPrefix + email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    // MARK: - Bound accounts

    func settings(for accountID: UUID) throws -> IMAPAccountSettings? {
        guard let data = try keychain.get(Self.settingsKeyPrefix + accountID.uuidString) else { return nil }
        return try? JSONDecoder().decode(IMAPAccountSettings.self, from: data)
    }

    func password(for accountID: UUID) throws -> String? {
        try keychain.getString(Self.passwordKeyPrefix + accountID.uuidString)
    }

    func credentials(for accountID: UUID) throws -> IMAPCredentials? {
        guard let settings = try settings(for: accountID), let password = try password(for: accountID) else { return nil }
        return IMAPCredentials(settings: settings, password: password)
    }

    /// Replaces whatever was stored for the account (a re-sign-in after a changed password).
    func store(_ credentials: IMAPCredentials, for accountID: UUID) throws {
        let encoded = try JSONEncoder().encode(credentials.settings)
        try keychain.set(encoded, for: Self.settingsKeyPrefix + accountID.uuidString)
        try keychain.setString(credentials.password, for: Self.passwordKeyPrefix + accountID.uuidString)
    }

    func delete(accountID: UUID) throws {
        try keychain.delete(Self.settingsKeyPrefix + accountID.uuidString)
        try keychain.delete(Self.passwordKeyPrefix + accountID.uuidString)
    }

    // MARK: - Pending sign-ins

    func storePending(_ pending: IMAPPendingSignIn) throws {
        let encoded = try JSONEncoder().encode(pending)
        try keychain.set(encoded, for: Self.pendingKey(for: pending.credentials.settings.email))
    }

    /// The live pending sign-in for an address, if any. An expired one is deleted and reported as missing.
    func takePending(email: String, now: Date = .now) throws -> IMAPPendingSignIn? {
        let key = Self.pendingKey(for: email)
        guard let data = try keychain.get(key) else { return nil }
        guard let pending = try? JSONDecoder().decode(IMAPPendingSignIn.self, from: data) else {
            try keychain.delete(key)
            return nil
        }
        guard now.timeIntervalSince(pending.createdAt) < Self.pendingLifetime else {
            try keychain.delete(key)
            return nil
        }
        try keychain.delete(key)
        return pending
    }

    func deletePending(email: String) throws {
        try keychain.delete(Self.pendingKey(for: email))
    }
}
