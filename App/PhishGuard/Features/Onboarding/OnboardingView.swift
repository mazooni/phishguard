import PhishCore
import SwiftData
import SwiftUI

/// First launch: what PhishGuard does → privacy promises → download the detection model → notification
/// permission → link an account. Skippable.
///
/// The model page is a gate, not a suggestion: a downloaded MLX model is the default classifier, and without it
/// every scan falls back to heuristics only. `ModelReadiness.canLeaveDownloadPage` decides when the page lets go —
/// when the model is on disk, when the user chose Apple Intelligence instead (offered only where it is actually
/// available), or in the Simulator, which cannot run local models at all. *Skip* still leaves the whole flow; the
/// Home banner catches that case.
struct OnboardingView: View {
    private static let pageCount = 5
    private static let modelPage = 2
    private static let accountsPage = 4

    @Environment(AppEnvironment.self) private var environment
    /// Real mailboxes only — onboarding asks the user to link one, and a Demo-mode account is not one.
    @Query(filter: #Predicate<LinkedAccount> { !$0.isDemo }, sort: \LinkedAccount.addedAt) private var accounts: [LinkedAccount]
    @State private var page = DemoData.initialOnboardingPage(pageCount: OnboardingView.pageCount)
    @State private var notificationsGranted: Bool?
    @State private var linker = AccountLinker()
    /// Tracks only the `Task`s this screen started; `ModelManager` owns the download itself, so swiping away from
    /// the page and back — or leaving onboarding entirely — does not interrupt it.
    @State private var downloads = ModelDownloadController()
    @State private var appleAvailability: ClassifierAvailability?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button("Skip") { finish() }
                    // Like the primary/provider buttons: leaving onboarding mid sign-in would tear down this view
                    // and the alert bound to `linker.errorMessage`, so a failed link would go unreported.
                    .disabled(linker.isBusy)
                    .accessibilityHint("Skips setup. You can link accounts and download the model later in Settings.")
                    .padding(.horizontal)
                    .padding(.top, 8)
            }

            TabView(selection: $page) {
                OnboardingPage(
                    symbol: "shield.lefthalf.filled",
                    tint: .accentColor,
                    title: "Your inbox, watched",
                    subtitle: "PhishGuard keeps an eye on new mail so you don't have to.",
                    bullets: [
                        ("envelope.badge.shield.half.filled", "Connects to Gmail or Outlook / Hotmail with read-only access."),
                        ("magnifyingglass", "Checks every new email for the tricks phishers and scammers use."),
                        ("bell.badge", "Alerts you only when an email looks like phishing or a scam."),
                        ("tray.and.arrow.down", "It is not a mail client: your mailbox is never changed."),
                    ]
                )
                .tag(0)

                OnboardingPage(
                    symbol: "lock.shield.fill",
                    tint: .green,
                    title: "Private by design",
                    subtitle: "Your mail never leaves this iPhone.",
                    bullets: [
                        ("eye", "Read-only. PhishGuard cannot send, move or delete mail."),
                        ("cpu", "Every check runs on this device, with a language model stored on the phone."),
                        ("trash.slash", "Emails are discarded right after the check. Nothing is stored except a short summary of flagged ones."),
                        ("key.fill", "Sign-in tokens stay in the iOS Keychain."),
                    ]
                )
                .tag(1)

                modelDownloadPage
                    .tag(Self.modelPage)

                notificationsPage
                    .tag(3)

                accountsPage
                    .tag(Self.accountsPage)
            }
            .tabViewStyle(.page(indexDisplayMode: .always))
            .indexViewStyle(.page(backgroundDisplayMode: .always))
            .animation(.default, value: page)
            // The page style lets the user swipe, so the gate has to hold there too, not only on Continue.
            .onChange(of: page) { _, newValue in
                if newValue > Self.modelPage, !canLeaveModelPage { page = Self.modelPage }
            }

            primaryButton
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
        }
        .background(Color(.systemGroupedBackground))
        .task {
            appleAvailability = await environment.classifierRegistry.classifier(for: .appleFoundation).availability()
        }
        .alert("Could not add account", isPresented: Binding(get: { linker.errorMessage != nil }, set: { if !$0 { linker.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(linker.errorMessage ?? "")
        }
    }

    // MARK: - Model download page

    /// The model `.mlx` will load: the user's catalog pick, otherwise `ModelManager.defaultModelID`.
    private var modelID: String { environment.classifierRegistry.preferredMLXModelID }

    private var modelEntry: ModelManager.CatalogEntry? { ModelManager.entry(for: modelID) }

    /// The observable copy of the on-disk state, so the page re-renders the moment a download finishes.
    private var downloadState: ModelManager.DownloadState {
        environment.modelManager.downloadStates[modelID] ?? .notDownloaded
    }

    private var modelIsDownloaded: Bool { downloadState == .downloaded }

    /// True between tapping Download and the manager publishing its first progress, too.
    private var modelIsDownloading: Bool {
        if case .downloading = downloadState { return true }
        return downloads.isDownloading(modelID)
    }

    private var downloadProgress: Double? {
        if case .downloading(let progress) = downloadState { return progress }
        return nil
    }

    private var downloadFailure: String? {
        if case .failed(let message) = downloadState { return message }
        return downloads.errorMessages[modelID]
    }

    private var usesAppleFoundation: Bool { environment.settings.classifierChoice == .appleFoundation }

    private var canLeaveModelPage: Bool {
        ModelReadiness.canLeaveDownloadPage(
            choice: environment.settings.classifierChoice,
            isModelDownloaded: modelIsDownloaded
        )
    }

    private var modelSizeText: String {
        modelEntry.map { ByteFormat.string($0.approxSizeBytes) } ?? "about 2.28 GB"
    }

    private var modelDownloadPage: some View {
        OnboardingPage(
            symbol: modelIsDownloaded ? "checkmark.seal.fill" : "arrow.down.circle",
            tint: modelIsDownloaded ? .green : .accentColor,
            title: "Download the detection model",
            subtitle: "PhishGuard reads every new email with a small language model. One \(modelSizeText) download, once.",
            bullets: [
                ("iphone", "It runs on this iPhone. No email text, link or address is ever uploaded."),
                ("wifi", "Best over Wi-Fi. It keeps downloading if you leave this page."),
                ("slider.horizontal.3", "Swap it for a smaller or larger model later in Settings."),
            ]
        ) {
            VStack(spacing: 12) {
                modelActionArea

                if let downloadFailure {
                    Text(downloadFailure)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if ModelReadiness.offersAppleFoundation(appleAvailability) {
                    appleFoundationAlternative
                }

                #if targetEnvironment(simulator)
                Text("Local models cannot run in the Simulator, so setup continues without the download. Use a physical iPhone to see real classifications.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                #endif
            }
        }
    }

    @ViewBuilder
    private var modelActionArea: some View {
        if modelIsDownloaded {
            Label("\(modelEntry?.displayName ?? "The model") is ready", systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
                .multilineTextAlignment(.center)
        } else if modelIsDownloading {
            VStack(spacing: 10) {
                if let downloadProgress {
                    ProgressView(value: downloadProgress) {
                        Text("Downloading…")
                    } currentValueLabel: {
                        Text("\(Int((downloadProgress * 100).rounded()))% of \(modelSizeText)")
                            .monospacedDigit()
                    }
                } else {
                    ProgressView("Starting download…")
                        .frame(maxWidth: .infinity)
                }
                Button("Cancel", role: .cancel) {
                    downloads.cancel(modelID, using: environment.modelManager)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
            }
        } else {
            Button {
                downloads.download(modelID, using: environment.modelManager)
            } label: {
                Label(
                    downloadFailure == nil ? "Download (\(modelSizeText))" : "Try again",
                    systemImage: downloadFailure == nil ? "arrow.down.circle" : "arrow.clockwise"
                )
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
    }

    /// Offered only where `AppleFoundationClassifier` reports `.available`, and reversible: picking it lets setup
    /// continue without the download, and the model can still be fetched here or in Settings afterwards.
    @ViewBuilder
    private var appleFoundationAlternative: some View {
        if usesAppleFoundation {
            VStack(spacing: 4) {
                Label("Using Apple Intelligence", systemImage: "apple.intelligence")
                    .font(.subheadline.weight(.semibold))
                // Back to the default this device would have started with: both models where Apple
                // Intelligence works, so changing one's mind here does not silently give up the second opinion.
                Button("Download the model instead") {
                    environment.settings.classifierChoice = SettingsStore.defaultClassifierChoice(
                        appleIntelligenceAvailable: ModelReadiness.offersAppleFoundation(appleAvailability)
                    )
                }
                .font(.footnote)
            }
        } else {
            Button("Use Apple Intelligence instead") {
                downloads.cancel(modelID, using: environment.modelManager)
                environment.settings.classifierChoice = .appleFoundation
            }
            .font(.subheadline)
        }
    }

    // MARK: - Other pages

    private var notificationsPage: some View {
        OnboardingPage(
            symbol: notificationsGranted == true ? "bell.badge.fill" : "bell.badge",
            tint: .orange,
            title: "Get alerted",
            subtitle: "A notification is the whole point: you'll hear from PhishGuard only when something looks wrong.",
            bullets: [
                ("bell.slash", "No digests, no reminders, no marketing."),
                ("hand.raised.fill", "Each alert says what was suspicious and why."),
            ]
        ) {
            VStack(spacing: 10) {
                Button {
                    Task { notificationsGranted = await environment.notificationManager.requestAuthorization() }
                } label: {
                    Label(notificationsGranted == true ? "Notifications enabled" : "Allow notifications", systemImage: "bell")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(notificationsGranted == true)

                if notificationsGranted == false {
                    Text("Notifications are off. You can turn them on later in Settings → Notifications → PhishGuard.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
        }
    }

    private var accountsPage: some View {
        OnboardingPage(
            symbol: "person.crop.circle.badge.plus",
            tint: .blue,
            title: "Link an account",
            subtitle: "Sign in with read-only access. You can add more accounts later in Settings.",
            bullets: []
        ) {
            VStack(spacing: 12) {
                // Both providers are offered the same way; a build missing that provider's OAuth client id says
                // so when the button is tapped (see `AccountLinker.unconfiguredMessage`).
                ForEach(MailProvider.allCases, id: \.self) { provider in
                    Button {
                        Task { _ = await linker.link(provider, in: environment) }
                    } label: {
                        HStack(spacing: 12) {
                            ProviderAvatar(provider: provider, diameter: 30)
                            Text(accounts.contains { $0.provider == provider } ? "Add another \(provider.displayName) account" : "Sign in with \(provider.displayName)")
                            Spacer()
                            if linker.busyProvider == provider {
                                ProgressView()
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(linker.isBusy)
                    .accessibilityLabel("Sign in with \(provider.displayName)")
                }

                if !accounts.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(accounts) { account in
                            Label(account.email, systemImage: "checkmark.circle.fill")
                                .font(.subheadline)
                                .foregroundStyle(.green)
                                .lineLimit(1)
                        }
                    }
                    .padding(.top, 4)
                    .accessibilityLabel("Linked accounts: \(accounts.map(\.email).joined(separator: ", "))")
                }
            }
        }
    }

    // MARK: - Actions

    private var primaryButton: some View {
        Button {
            if page < Self.pageCount - 1 {
                page += 1
            } else {
                finish()
            }
        } label: {
            Text(primaryTitle)
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .disabled(linker.isBusy || (page == Self.modelPage && !canLeaveModelPage))
    }

    private var primaryTitle: String {
        if page < Self.pageCount - 1 { return "Continue" }
        return accounts.isEmpty ? "Do this later" : "Done"
    }

    private func finish() {
        environment.settings.hasCompletedOnboarding = true
    }
}

/// One onboarding page: symbol, title, bullet list and an optional action area.
private struct OnboardingPage<Actions: View>: View {
    let symbol: String
    let tint: Color
    let title: String
    let subtitle: String
    let bullets: [(String, String)]
    let actions: Actions

    init(symbol: String, tint: Color, title: String, subtitle: String, bullets: [(String, String)], @ViewBuilder actions: () -> Actions) {
        self.symbol = symbol
        self.tint = tint
        self.title = title
        self.subtitle = subtitle
        self.bullets = bullets
        self.actions = actions()
    }

    init(symbol: String, tint: Color, title: String, subtitle: String, bullets: [(String, String)]) where Actions == EmptyView {
        self.init(symbol: symbol, tint: tint, title: title, subtitle: subtitle, bullets: bullets) { EmptyView() }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: symbol)
                    .font(.system(size: 64))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(tint)
                    .padding(.top, 24)
                    .accessibilityHidden(true)
                VStack(spacing: 8) {
                    Text(title)
                        .font(.largeTitle.bold())
                        .multilineTextAlignment(.center)
                    Text(subtitle)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                if !bullets.isEmpty {
                    VStack(alignment: .leading, spacing: 14) {
                        ForEach(Array(bullets.enumerated()), id: \.offset) { _, bullet in
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: bullet.0)
                                    .font(.title3)
                                    .frame(width: 30)
                                    .foregroundStyle(tint)
                                    .accessibilityHidden(true)
                                Text(bullet.1)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .padding(16)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                }
                actions
            }
            .padding(.horizontal, 24)
            // Clears the page-dot index view, which floats over the bottom of every page.
            .padding(.bottom, 56)
        }
    }
}

#Preview {
    OnboardingView()
        .environment(AppEnvironment.preview())
        .modelContainer(AppEnvironment.preview().container)
}
