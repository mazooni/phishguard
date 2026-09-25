import Foundation
import Observation
import OSLog
import PhishCore
import SwiftData
import UIKit

/// Links and removes mail accounts. Shared by Onboarding and Settings → Accounts.
/// Sign-in is presented from the key window's top view controller (`UIApplication.phishGuardTopViewController`).
@MainActor
@Observable
final class AccountLinker {
    private(set) var busyProvider: MailProvider?
    var errorMessage: String?

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "accounts")

    init() {}

    var isBusy: Bool { busyProvider != nil }

    static func isConfigured(_ provider: MailProvider, config: AppConfig) -> Bool {
        switch provider {
        case .gmail: return config.isGoogleConfigured
        case .microsoft: return config.isMicrosoftConfigured
        // IMAP needs no client id or redirect scheme: the user types the server and the password.
        case .imap: return true
        }
    }

    /// Shown *when the option is tapped* and this build has no OAuth client id for the provider.
    ///
    /// Deliberately not a disabled button: every provider is fully implemented (AppAuth and history sync for
    /// Gmail; MSAL sign-in, delta sync and subscriptions for Microsoft; a read-only IMAP client for the rest),
    /// and only a build-time client id can be missing. Greying the option out claims the feature does not exist,
    /// which is untrue and reads as broken. So every option looks and behaves the same, and the missing piece is
    /// named at the point of use, where it is actionable. Diagnostics › Configuration reports it at a glance.
    /// IMAP needs no client id at all (`isConfigured` is always true for it), so it never reaches this.
    static func unconfiguredMessage(for provider: MailProvider) -> String {
        switch provider {
        case .gmail:
            return "Gmail sign-in needs a Google OAuth client id (GOOGLE_CLIENT_ID) in "
                + "App/PhishGuard/Config/Secrets.xcconfig. See docs/SETUP.md §2."
        case .microsoft:
            return "Outlook / Hotmail sign-in needs a Microsoft client id (MS_CLIENT_ID) in "
                + "App/PhishGuard/Config/Secrets.xcconfig. See docs/SETUP.md §3."
        case .imap:
            return ""
        }
    }

    /// Label for the "add account" rows. IMAP is named for what it is for — any other mailbox.
    static func addTitle(for provider: MailProvider) -> String {
        switch provider {
        case .gmail, .microsoft: return "Add \(provider.displayName)"
        case .imap: return "Add another mail account (IMAP)"
        }
    }

    /// Runs the provider's OAuth sign-in, creates (or re-enables) the `LinkedAccount`, binds the fresh credentials
    /// to its id, registers it with the relay and starts a first scan. Signing in again as an address that is
    /// already linked re-uses that account and replaces its stored credentials (the "Sign in again" path after a
    /// revoked or expired grant). Returns nil when the user cancelled or an error occurred (`errorMessage` is set).
    @discardableResult
    func link(_ kind: MailProvider, in environment: AppEnvironment) async -> LinkedAccount? {
        guard !isBusy else { return nil }
        guard Self.isConfigured(kind, config: environment.config) else {
            errorMessage = Self.unconfiguredMessage(for: kind)
            return nil
        }
        guard let provider = environment.providers[kind] else {
            errorMessage = "No sign-in provider is registered for \(kind.displayName)."
            return nil
        }
        guard let presenter = UIApplication.shared.phishGuardTopViewController else {
            errorMessage = "No window is available to present the sign-in screen."
            return nil
        }

        busyProvider = kind
        defer { busyProvider = nil }

        do {
            let identity = try await provider.signIn(presenting: presenter)
            let context = environment.container.mainContext
            let account = try await Self.linkIdentity(identity, kind: kind, provider: provider, config: environment.config, in: context)
            logger.info("Linked \(kind.rawValue, privacy: .public) account \(account.id.uuidString, privacy: .public)")

            // Providers without a webhook (IMAP) have nothing to register: the relay only rings for push.
            if let key = account.relayAccountKey, kind.supportsPushSubscriptions, environment.relayClient.isConfigured {
                do {
                    try await environment.relayClient.registerAccount(accountKey: key, provider: kind)
                } catch {
                    logger.error("Relay account registration failed: \(error.localizedDescription, privacy: .public)")
                }
            }
            let accountID = account.id
            Task { await environment.runScan(trigger: .manual, accountIDs: [accountID]) }
            return account
        } catch ProviderError.cancelled {
            return nil
        } catch {
            logger.error("Sign-in failed for \(kind.rawValue, privacy: .public): \(error.localizedDescription, privacy: .private)")
            errorMessage = error.localizedDescription
            return nil
        }
    }

    /// Signs the account out, unregisters it from the relay and deletes it together with its flagged records.
    func remove(_ account: LinkedAccount, in environment: AppEnvironment) async {
        let accountID = account.id
        let relayKey = account.relayAccountKey
        let provider = account.provider.flatMap { environment.providers[$0] }
        let context = environment.container.mainContext

        do {
            let recordIDs = try Self.deleteRecords(for: accountID, in: context)
            for recordID in recordIDs {
                environment.notificationManager.clearAlert(recordID: recordID)
            }
        } catch {
            logger.error("Deleting records for account \(accountID.uuidString, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
        context.delete(account)
        do {
            try context.save()
        } catch {
            errorMessage = "Could not remove the account: \(error.localizedDescription)"
            return
        }

        do {
            try await provider?.signOut(accountID: accountID)
        } catch {
            logger.notice("Sign-out failed for \(accountID.uuidString, privacy: .public): \(error.localizedDescription, privacy: .private)")
        }
        if let relayKey, environment.relayClient.isConfigured {
            do {
                try await environment.relayClient.unregisterAccount(accountKey: relayKey)
            } catch {
                logger.notice("Relay unregister failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: - Persistence helpers

    /// Binds the credentials `signIn` just produced to the `LinkedAccount` id for `identity` (the existing account
    /// for that provider + address, or a fresh id), then upserts and saves the account. Binding comes FIRST and
    /// synchronously: a re-sign-in replaces revoked tokens under the same id, a sign-in can never be claimed by
    /// another account, and a binding failure leaves the store untouched (no unusable account is created or
    /// re-enabled).
    static func linkIdentity(
        _ identity: SignedInIdentity,
        kind: MailProvider,
        provider: any MailAccountProvider,
        config: AppConfig,
        in context: ModelContext
    ) async throws -> LinkedAccount {
        let accountID = try existingAccount(for: kind, email: identity.email, in: context)?.id ?? UUID()
        try await provider.linkAccount(accountID: accountID, identity: identity)
        let account = try upsertAccount(for: kind, identity: identity, config: config, in: context, newAccountID: accountID)
        try context.save()
        return account
    }

    /// The account for `kind` + `email` (case-insensitive), if any. Never the Demo-mode account: a real sign-in
    /// must create a real account rather than take over the fictional one.
    static func existingAccount(for kind: MailProvider, email: String, in context: ModelContext) throws -> LinkedAccount? {
        let raw = kind.rawValue
        return try context.fetch(FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.providerRaw == raw && !$0.isDemo }))
            .first { $0.email.caseInsensitiveCompare(email) == .orderedSame }
    }

    /// Creates the account (with `newAccountID`), or re-enables an existing one for the same provider + address
    /// (case-insensitive). A re-link always follows a fresh sign-in, so the account no longer needs re-authentication.
    static func upsertAccount(
        for kind: MailProvider,
        identity: SignedInIdentity,
        config: AppConfig,
        in context: ModelContext,
        newAccountID: UUID = UUID()
    ) throws -> LinkedAccount {
        let account: LinkedAccount
        if let existing = try existingAccount(for: kind, email: identity.email, in: context) {
            existing.isEnabled = true
            existing.needsReauthentication = false
            if let name = identity.displayName { existing.displayName = name }
            account = existing
        } else {
            account = LinkedAccount(id: newAccountID, provider: kind, email: identity.email, displayName: identity.displayName)
            context.insert(account)
        }
        account.relayAccountKey = config.accountKey(for: identity.email)
        return account
    }

    /// Deletes every `FlaggedEmailRecord` and `ProcessedMessage` belonging to the account. Returns the deleted record ids.
    @discardableResult
    static func deleteRecords(for accountID: UUID, in context: ModelContext) throws -> [UUID] {
        let records = try context.fetch(FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.accountID == accountID }))
        let ids = records.map(\.id)
        for record in records {
            context.delete(record)
        }
        let marker = ":\(accountID.uuidString):"
        let processed = try context.fetch(FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key.contains(marker) }))
        for entry in processed {
            context.delete(entry)
        }
        try context.save()
        return ids
    }
}
