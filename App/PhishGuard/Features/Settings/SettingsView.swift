import PhishCore
import SwiftData
import SwiftUI
import UIKit
import UserNotifications

struct SettingsView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.scenePhase) private var scenePhase
    /// Real mailboxes only: the Demo-mode account is not one, so it is never part of this count (the Accounts
    /// screen lists it, labelled "Demo").
    @Query(filter: #Predicate<LinkedAccount> { !$0.isDemo }) private var accounts: [LinkedAccount]
    @State private var notificationStatus: UNAuthorizationStatus?
    @State private var backgroundRefreshStatus: UIBackgroundRefreshStatus?
    #if DEBUG
    /// One line of feedback under the Demo controls ("13 sample emails added", "lock the phone now", …).
    @State private var demoMessage: String?
    /// Which bundled scam call "Simulate a scam call" delivers.
    @State private var demoCallScenario: DemoScenario = DemoCalls.scenarios[0].id
    #endif

    private var alertLevels: [RiskLevel] { RiskLevel.allCases.filter { $0 != .safe } }

    var body: some View {
        @Bindable var settings = environment.settings
        Form {
            Section {
                ForEach(alertLevels, id: \.self) { level in
                    Button {
                        settings.alertMinimumLevel = level
                    } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: level.symbolName)
                                .foregroundStyle(level.color)
                                .frame(width: 24)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(level.displayName) and above")
                                    .foregroundStyle(.primary)
                                Text(level.alertDescription)
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            if settings.alertMinimumLevel == level {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(.tint)
                                    .accessibilityHidden(true)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(settings.alertMinimumLevel == level ? [.isSelected] : [])
                }
            } header: {
                Text("Alerts")
            } footer: {
                Text("Every new email is still checked; emails below this level are neither listed nor notified.")
            }

            Section {
                Stepper(value: $settings.lookbackHours, in: SettingsStore.lookbackRange) {
                    LabeledContent("Look back", value: "\(settings.lookbackHours) h")
                }
                RecheckRecentEmailButton()
            } header: {
                Text("Scanning")
            } footer: {
                Text("How far back to check when an account is first added, its sync position expired, or you "
                     + "re-check email PhishGuard has already seen.")
            }

            Section {
                NavigationLink {
                    AccountsView()
                } label: {
                    LabeledContent {
                        Text(accounts.isEmpty ? "None" : "\(accounts.count)")
                    } label: {
                        Label("Accounts", systemImage: "person.crop.circle")
                    }
                }
                NavigationLink {
                    ModelSettingsView()
                } label: {
                    LabeledContent {
                        Text(settings.classifierChoice.shortName)
                    } label: {
                        Label("Detection model", systemImage: "brain")
                    }
                }
            }

            Section {
                LabeledContent {
                    statusLabel(backgroundRefreshText, ok: backgroundRefreshStatus == .available)
                } label: {
                    Label("Background App Refresh", systemImage: "arrow.clockwise.circle")
                }
                LabeledContent {
                    statusLabel(notificationText, ok: notificationsAllowed)
                } label: {
                    Label("Notifications", systemImage: "bell.badge")
                }
                if notificationStatus == .notDetermined {
                    Button {
                        Task {
                            _ = await environment.notificationManager.requestAuthorization()
                            await refreshStatuses()
                        }
                    } label: {
                        Label("Enable notifications", systemImage: "bell")
                    }
                }
                if let url = URL(string: UIApplication.openNotificationSettingsURLString) {
                    Link(destination: url) {
                        Label("Open Settings", systemImage: "gear")
                    }
                }
            } header: {
                Text("Background & notifications")
            } footer: {
                Text("PhishGuard checks mail when iOS runs its background refresh and when the relay signals new mail. Alerts need notification permission.")
            }

            Section {
                privacyRow("eye", "Read-only access. PhishGuard can never send, move or delete mail.")
                privacyRow("cpu", "Every email is analyzed on this iPhone. Nothing is uploaded to PhishGuard or anyone else.")
                privacyRow("trash.slash", "Emails are discarded after the check. Only sender, subject and the reasons of flagged emails are kept.")
                privacyRow("key.fill", "Sign-in tokens live in the iOS Keychain. The optional relay only learns a salted hash of your address.")
            } header: {
                Text("Privacy")
            }

            Section {
                NavigationLink {
                    DiagnosticsView()
                } label: {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
            }

            #if DEBUG
            demoSection
            #endif

            Section {
                LabeledContent("Version", value: versionText)
                Text("PhishGuard is a watchdog, not a mail client. It looks for phishing and scams in new mail and tells you when something looks wrong.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("About")
            }
        }
        .navigationTitle("Settings")
        .task {
            await refreshStatuses()
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task { await refreshStatuses() }
            }
        }
    }

    // MARK: - Demo (debug builds only)

    #if DEBUG
    /// Demonstrating PhishGuard on a real phone, on top of a real mailbox.
    ///
    /// The whole section — and `DemoMode`, `DemoArrivalPool` and `DemoAlertDelay` with it — is compiled out of
    /// release builds, so it can never ship. Everything it inserts is marked `isDemo`, which is the only thing
    /// the toggle's "off" position deletes; real flagged emails and real accounts are never touched.
    @ViewBuilder
    private var demoSection: some View {
        @Bindable var settings = environment.settings
        Section {
            Toggle(isOn: demoModeBinding) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Demo mode")
                    Text("Adds sample flagged emails for demonstrations. Your real mail is never touched.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Picker(selection: $settings.demoAlertDelaySeconds) {
                ForEach(DemoAlertDelay.allCases) { delay in
                    Text(delay.label).tag(delay.rawValue)
                }
            } label: {
                Label("Alert arrives", systemImage: "timer")
            }
            .pickerStyle(.menu)

            Button {
                simulateIncomingAlert()
            } label: {
                Label("Simulate an incoming flagged email", systemImage: "bell.and.waves.left.and.right")
            }
            .disabled(!settings.isDemoModeEnabled)

            Picker(selection: $demoCallScenario) {
                ForEach(DemoCalls.scenarios) { scenario in
                    Text(scenario.title).tag(scenario.id)
                }
            } label: {
                Label("Scam call scenario", systemImage: "phone")
            }
            .pickerStyle(.menu)

            Button {
                simulateIncomingCall()
            } label: {
                Label("Simulate a scam call", systemImage: "phone.badge.waveform")
            }
            .disabled(!settings.isDemoModeEnabled)

            if let demoMessage {
                Text(demoMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            Text("Demo")
        } footer: {
            Text("Debug builds only. The simulated email is a bundled sample put through the real analyzer and "
                 + "verdict engine, so the alert, the confidence and the reasons are genuine — it is just not "
                 + "from your mailbox. The simulated scam call is a bundled scenario with a recorded verdict; it "
                 + "posts the same urgent notification the relay's push produces, and nothing leaves the phone. "
                 + "Turning Demo mode off removes every sample email, every sample call and the demo account.")
        }
    }

    /// Seeds on, purges off. Both run synchronously on the main context so the list has already changed by the
    /// time the switch finishes animating.
    private var demoModeBinding: Binding<Bool> {
        Binding(
            get: { environment.settings.isDemoModeEnabled },
            set: { isOn in
                let change = DemoMode.setEnabled(isOn, in: environment)
                demoMessage = isOn
                    ? "Added \(change.records) sample flagged emails, \(change.calls) sample calls and one demo account. Real mail, real calls and real accounts are untouched."
                    : "Removed \(change.records) sample \(change.records == 1 ? "email" : "emails"), \(change.calls) sample \(change.calls == 1 ? "call" : "calls") and \(change.accounts) demo \(change.accounts == 1 ? "account" : "accounts")."
            }
        )
    }

    private func simulateIncomingCall() {
        guard let scenario = DemoCalls.scenario(demoCallScenario) else { return }
        let settings = environment.settings
        let delay = DemoAlertDelay(rawValue: settings.demoAlertDelaySeconds) ?? .default
        let call = DemoMode.simulateIncomingCall(
            scenario,
            in: environment.container.mainContext,
            notifications: environment.notificationManager,
            delay: delay.seconds
        )
        var message = delay.callConfirmation
        if !notificationsAllowed {
            message += " Notifications are off, so nothing will appear — turn them on above."
        }
        demoMessage = "\(call.alert.title) from \(PhoneNumberFormat.display(call.record.callerNumber)) — \(message)"
    }

    private func simulateIncomingAlert() {
        let settings = environment.settings
        let delay = DemoAlertDelay(rawValue: settings.demoAlertDelaySeconds) ?? .default
        let arrival = DemoMode.simulateIncomingAlert(
            in: environment.container.mainContext,
            notifications: environment.notificationManager,
            delay: delay.seconds,
            arrivalNumber: settings.demoSimulatedArrivalCount
        )
        settings.demoSimulatedArrivalCount += 1
        var message = delay.confirmation
        if !notificationsAllowed {
            message += " Notifications are off, so nothing will appear — turn them on above."
        }
        demoMessage = "\(arrival.record.subject) — \(message)"
    }
    #endif

    // MARK: - Status helpers

    private var notificationsAllowed: Bool {
        switch notificationStatus {
        case .authorized?, .provisional?, .ephemeral?: return true
        default: return false
        }
    }

    private var notificationText: String {
        switch notificationStatus {
        case .authorized?: return "Allowed"
        case .provisional?: return "Quiet delivery"
        case .ephemeral?: return "Temporary"
        case .denied?: return "Off"
        case .notDetermined?: return "Not asked yet"
        case nil: return "…"
        @unknown default: return "Unknown"
        }
    }

    private var backgroundRefreshText: String {
        switch backgroundRefreshStatus {
        case .available?: return "On"
        case .denied?: return "Off"
        case .restricted?: return "Restricted"
        case nil: return "…"
        @unknown default: return "Unknown"
        }
    }

    private func statusLabel(_ text: String, ok: Bool) -> some View {
        Label(text, systemImage: ok ? "checkmark.circle.fill" : "exclamationmark.circle")
            .foregroundStyle(ok ? Color.green : Color.orange)
            .labelStyle(.titleAndIcon)
    }

    private func privacyRow(_ symbol: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .foregroundStyle(.tint)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text(text)
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
    }

    private var versionText: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
        return "\(version) (\(build))"
    }

    private func refreshStatuses() async {
        backgroundRefreshStatus = UIApplication.shared.backgroundRefreshStatus
        notificationStatus = await environment.notificationManager.authorizationStatus()
    }
}

#Preview {
    let environment = AppEnvironment.preview()
    return NavigationStack {
        SettingsView()
    }
    .environment(environment)
    .modelContainer(environment.container)
}
