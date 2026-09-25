import PhishCore
import SwiftData
import SwiftUI

/// Linked accounts: add (OAuth sign-in), enable/disable, sign in again when a grant lapsed, remove (sign out +
/// delete that account's alerts).
struct AccountsView: View {
    @Environment(AppEnvironment.self) private var environment
    @Query(sort: \LinkedAccount.addedAt) private var accounts: [LinkedAccount]
    @State private var linker = AccountLinker()
    @State private var accountToRemove: LinkedAccount?

    var body: some View {
        List {
            if accounts.isEmpty {
                Section {
                    ContentUnavailableView(
                        "No accounts yet",
                        systemImage: "person.crop.circle.badge.plus",
                        description: Text("Add a Gmail or Outlook / Hotmail account to start watching for phishing. Access is read-only.")
                    )
                }
                .listRowBackground(Color.clear)
            } else {
                Section {
                    ForEach(accounts) { account in
                        AccountRow(account: account, isLinkerBusy: linker.isBusy, onSignInAgain: { signInAgain(account) })
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    accountToRemove = account
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                    }
                } header: {
                    Text("Watched accounts")
                } footer: {
                    Text("Turn an account off to pause scanning without signing out. Swipe left to remove it."
                         + (accounts.contains(where: \.isDemo)
                            ? " A row marked Demo is sample data, not a mailbox — it is never scanned, and Settings → Demo removes it."
                            : ""))
                }
            }

            Section {
                // Every provider is offered the same way. A build without that provider's OAuth client id says
                // so when the row is tapped (`AccountLinker.link` → the alert below), because the integration
                // exists and only a build-time secret is missing — a greyed-out row would say the opposite.
                ForEach(MailProvider.allCases, id: \.self) { provider in
                    Button {
                        Task { _ = await linker.link(provider, in: environment) }
                    } label: {
                        HStack(spacing: 12) {
                            ProviderAvatar(provider: provider, diameter: 32)
                            Text(AccountLinker.addTitle(for: provider))
                                .foregroundStyle(.primary)
                            Spacer()
                            if linker.busyProvider == provider {
                                ProgressView()
                            }
                        }
                    }
                    .disabled(linker.isBusy)
                }
            } header: {
                Text("Add account")
            } footer: {
                Text("Every account is opened read-only — Gmail (gmail.readonly), Outlook (Mail.Read) and IMAP "
                     + "alike, so PhishGuard can never send, move or delete mail. Credentials stay in the device Keychain.")
            }
        }
        .navigationTitle("Accounts")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    ForEach(MailProvider.allCases, id: \.self) { provider in
                        Button {
                            Task { _ = await linker.link(provider, in: environment) }
                        } label: {
                            Label(AccountLinker.addTitle(for: provider), systemImage: provider.symbolName)
                        }
                    }
                } label: {
                    Label("Add account", systemImage: "plus")
                }
                .disabled(linker.isBusy)
            }
        }
        .confirmationDialog(
            "Remove \(accountToRemove?.email ?? "this account")?",
            isPresented: Binding(get: { accountToRemove != nil }, set: { if !$0 { accountToRemove = nil } }),
            titleVisibility: .visible,
            presenting: accountToRemove
        ) { account in
            Button("Remove account and its alerts", role: .destructive) {
                Task { await linker.remove(account, in: environment) }
            }
        } message: { _ in
            Text("PhishGuard signs out and deletes every alert for this account. Your mailbox is not changed.")
        }
        // Same title as onboarding's: what reaches it is usually "this build has no client id for that provider"
        // or a cancelled/failed sign-in, and neither is an error with the account.
        .alert("Could not add account", isPresented: Binding(get: { linker.errorMessage != nil }, set: { if !$0 { linker.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(linker.errorMessage ?? "")
        }
    }

    /// Same sign-in flow as "Add": the address already exists, so the account is re-used and the fresh credentials
    /// replace the revoked ones (`AccountLinker.linkIdentity`).
    private func signInAgain(_ account: LinkedAccount) {
        guard let kind = account.provider else { return }
        Task { _ = await linker.link(kind, in: environment) }
    }
}

private struct AccountRow: View {
    @Bindable var account: LinkedAccount
    var isLinkerBusy: Bool
    var onSignInAgain: () -> Void

    private var pushStatus: PushSubscriptionStatus {
        .make(
            expiresAt: account.pushSubscriptionExpiresAt,
            supportsPush: account.provider?.supportsPushSubscriptions ?? true
        )
    }

    private var lastScanText: String {
        // A demo account is never fetched, so any `lastScanAt` on it is seeded decoration; saying "last scan a
        // minute ago" about a mailbox that does not exist is exactly the impression this row must not give.
        if account.isDemo { return "Never scanned — sample data only" }
        guard let last = account.lastScanAt else { return "Not scanned yet" }
        return "Last scan \(last.formatted(.relative(presentation: .named)))"
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ProviderAvatar(provider: account.provider ?? .gmail)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: $account.isEnabled) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(account.displayName ?? account.email)
                                .font(.headline)
                                .lineLimit(1)
                            if account.isDemo {
                                Text("Demo")
                                    .font(.caption2.weight(.semibold))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.secondary.opacity(0.18), in: Capsule())
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Text(account.email)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .accessibilityLabel("\(account.isDemo ? "Demo " : "")\(account.provider?.displayName ?? account.providerRaw) account \(account.email), \(account.isEnabled ? "enabled" : "paused")\(account.needsReauthentication ? ", needs sign-in" : "")")
                if account.isDemo {
                    Label("Sample data for demonstrations — no mailbox, never scanned", systemImage: "theatermasks")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if account.needsReauthentication {
                    Label("Needs sign-in: the provider no longer accepts this account's access", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Sign in again", action: onSignInAgain)
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        .disabled(isLinkerBusy)
                        .accessibilityHint("Runs the \(account.provider?.displayName ?? account.providerRaw) sign-in for \(account.email)")
                } else {
                    Label(pushStatus.label, systemImage: pushStatus.symbolName)
                        .font(.caption)
                        .foregroundStyle(pushStatus.color)
                }
                Label(lastScanText, systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    let environment = AppEnvironment.preview()
    DemoData.seed(into: environment.container)
    return NavigationStack {
        AccountsView()
    }
    .environment(environment)
    .modelContainer(environment.container)
}
