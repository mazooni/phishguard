import PhishCore
import SwiftUI
import UIKit
import UserNotifications

/// Configuration checklist, last scan details, a "test scan" over the bundled sample emails (nothing is persisted),
/// a re-check of mail the app has already seen, a test notification, the debug evaluation trace and an
/// onboarding reset.
struct DiagnosticsView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.scenePhase) private var scenePhase
    @State private var sampleResults: [SampleResult] = []
    @State private var isRunningSamples = false
    @State private var notificationStatus: UNAuthorizationStatus?
    @State private var backgroundRefreshStatus: UIBackgroundRefreshStatus?
    @State private var testNotificationMessage: String?
    @State private var showResetConfirmation = false
    #if DEBUG
    @State private var evaluations: [EvaluationTrace] = []
    #endif

    private struct SampleResult: Identifiable {
        let id: String
        let subject: String
        let verdict: Verdict
    }

    var body: some View {
        List {
            Section {
                checkRow("Google sign-in", ok: environment.config.isGoogleConfigured, detail: environment.config.isGoogleConfigured ? "Configured" : "GOOGLE_CLIENT_ID missing")
                checkRow("Microsoft sign-in", ok: environment.config.isMicrosoftConfigured, detail: environment.config.isMicrosoftConfigured ? "Configured" : "MS_CLIENT_ID missing")
                checkRow("Relay (silent push)", ok: environment.relayClient.isConfigured, detail: environment.relayClient.isConfigured ? "Configured" : "Not configured; background refresh only")
                checkRow("Call protection", ok: environment.callGuard.status.isProtected, detail: callProtectionText)
                checkRow("Notification permission", ok: notificationsAllowed, detail: notificationText)
                checkRow("Background App Refresh", ok: backgroundRefreshStatus == .available, detail: backgroundRefreshText)
                LabeledContent("Active classifier", value: ClassifierDisplay.name(forIdentifier: environment.classifierRegistry.activeClassifier().identifier))
                LabeledContent("Bundle", value: environment.config.bundleIdentifier)
                LabeledContent("Refresh task", value: environment.backgroundTasks.refreshIdentifier)
                LabeledContent("Processing task", value: environment.backgroundTasks.processingIdentifier)
            } header: {
                Text("Configuration")
            } footer: {
                Text(backgroundCheckNote)
            }

            Section("Last scan") {
                if let summary = environment.lastScanSummary {
                    LabeledContent("When", value: environment.lastScanDate?.formatted(date: .abbreviated, time: .shortened) ?? "–")
                    LabeledContent("Checked", value: "\(summary.scanned)")
                    LabeledContent("Flagged", value: "\(summary.flagged)")
                    LabeledContent("Hit deadline", value: summary.deadlineReached ? "Yes" : "No")
                    ForEach(Array(summary.errors.enumerated()), id: \.offset) { _, error in
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                } else {
                    Text("No scan has run yet.")
                        .foregroundStyle(.secondary)
                }
                Button {
                    Task { await environment.runScan(trigger: .manual) }
                } label: {
                    if environment.isScanning {
                        Label { Text("Scanning…") } icon: { ProgressView().controlSize(.small) }
                    } else {
                        Label("Scan now", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(environment.isScanning)
            }

            Section {
                Button {
                    runSamples()
                } label: {
                    if isRunningSamples {
                        Label { Text("Running…") } icon: { ProgressView().controlSize(.small) }
                    } else {
                        Label("Run test scan", systemImage: "testtube.2")
                    }
                }
                .disabled(isRunningSamples)
                ForEach(sampleResults) { result in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            RiskBadge(level: result.verdict.level, size: .compact)
                            CategoryChip(category: result.verdict.category)
                            Spacer()
                            Text("\(Int((result.verdict.confidence * 100).rounded()))%")
                                .font(.subheadline.monospacedDigit().weight(.semibold))
                                .foregroundStyle(result.verdict.level.color)
                        }
                        Text(result.subject)
                            .font(.subheadline.weight(.medium))
                        Text(result.verdict.summary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(ClassifierDisplay.name(forIdentifier: result.verdict.modelIdentifier))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.vertical, 2)
                    .accessibilityElement(children: .combine)
                }
            } header: {
                Text("Test scan")
            } footer: {
                Text("Runs the full analyze → classify → verdict pipeline on \(SampleEmails.all.count) bundled sample emails. Nothing is saved or notified.")
            }

            Section {
                RecheckRecentEmailButton()
            } header: {
                Text("Re-check")
            } footer: {
                Text("PhishGuard records every message it has checked and never looks at it again, and each "
                     + "account remembers where it got to. Re-checking clears both for your enabled accounts "
                     + "and scans the look-back window from scratch — use it after changing the detection "
                     + "model, or when a scan was interrupted. Emails already listed are updated, not "
                     + "duplicated.")
            }

            #if DEBUG
            evaluationsSection
            #endif

            Section {
                Button {
                    sendTestNotification()
                } label: {
                    Label("Send test notification", systemImage: "bell.badge")
                }
                if let testNotificationMessage {
                    Text(testNotificationMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button("Schedule app refresh (≥ 15 min)") { environment.backgroundTasks.scheduleAppRefresh() }
                Button("Schedule processing task") { environment.backgroundTasks.scheduleProcessing() }
            } header: {
                Text("Background & notifications")
            } footer: {
                Text("On a device, pause in Xcode and run: e -l objc -- (void)[[BGTaskScheduler sharedScheduler] _simulateLaunchForTaskWithIdentifier:@\"\(environment.backgroundTasks.refreshIdentifier)\"]")
            }

            Section {
                Button(role: .destructive) {
                    showResetConfirmation = true
                } label: {
                    Label("Reset onboarding", systemImage: "arrow.counterclockwise")
                }
            } footer: {
                Text("Shows the welcome flow again on next launch. Accounts and alerts are kept.")
            }
        }
        .navigationTitle("Diagnostics")
        .task {
            await refreshStatuses()
        }
        .onChange(of: environment.isScanning) { _, scanning in
            guard !scanning else { return }
            #if DEBUG
            Task { await refreshEvaluations() }
            #endif
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task { await refreshStatuses() }
            }
        }
        .confirmationDialog("Reset onboarding?", isPresented: $showResetConfirmation, titleVisibility: .visible) {
            Button("Reset onboarding", role: .destructive) {
                environment.settings.hasCompletedOnboarding = false
            }
        } message: {
            Text("The welcome flow is shown immediately. Your accounts and alerts are not affected.")
        }
    }

    // MARK: - Recent evaluations (debug only)

    #if DEBUG
    /// The panel that answers "why was this email not flagged?": every message this build evaluated, with the
    /// rule score and its signals, what each model answered, and the fused verdict. In memory only, never
    /// persisted, never any body text, and compiled out of release builds.
    @ViewBuilder
    private var evaluationsSection: some View {
        Section {
            if evaluations.isEmpty {
                Text("Nothing evaluated yet. Run a scan, a re-check or the test scan above.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(evaluations) { trace in
                    EvaluationTraceRow(trace: trace)
                }
            }
            HStack {
                Button("Refresh") {
                    Task { await refreshEvaluations() }
                }
                Spacer()
                Button("Clear", role: .destructive) {
                    Task {
                        await environment.scanCoordinator.clearEvaluationTraces()
                        await refreshEvaluations()
                    }
                }
                .disabled(evaluations.isEmpty)
            }
        } header: {
            Text("Recent evaluations (debug)")
        } footer: {
            Text("The last \(ScanCoordinator.evaluationTraceCapacity) messages this build evaluated, newest "
                 + "first: the rule score with its signal ids, what each model answered, and the fused "
                 + "verdict. Kept in memory only — never saved, never logged, and no message body is recorded.")
        }
    }

    /// Newest first, which is the opposite of the coordinator's ring buffer.
    private func refreshEvaluations() async {
        evaluations = await environment.scanCoordinator.evaluationTraces.reversed()
    }
    #endif

    // MARK: - Status helpers

    /// What the user gets when an email arrives while PhishGuard is closed. A downloaded model cannot run then
    /// (iOS only lets an app use the GPU while it is open), so background checks are the rule engine's.
    private var backgroundCheckNote: String {
        switch environment.settings.classifierChoice {
        case .both:
            return "While PhishGuard is open both models check every email. While it is closed only Apple "
                + "Intelligence can (where this iPhone has it); the downloaded model takes another look the "
                + "next time you open the app."
        case .mlx:
            return "The downloaded model runs only while PhishGuard is open. Emails that arrive while it is closed "
                + "are checked with the built-in rules, and the model takes another look the next time you open the app."
        case .appleFoundation:
            return "Apple Intelligence also checks email while PhishGuard is closed."
        case .heuristicsOnly:
            return "The built-in rules check email whether PhishGuard is open or closed."
        }
    }

    private var notificationsAllowed: Bool {
        switch notificationStatus {
        case .authorized?, .provisional?, .ephemeral?: return true
        default: return false
        }
    }

    /// Call Guard needs the relay and a registered line (docs/CALLS.md §8).
    private var callProtectionText: String {
        let callGuard = environment.callGuard
        switch callGuard.status {
        case .relayNotConfigured: return "Relay missing"
        case .notSetUp:
            guard callGuard.hasFetchedLine else { return "…" }
            return callGuard.lastError ?? "No guard number set up"
        case .protected(let guardNumber, _): return "Configured (\(PhoneNumberFormat.display(guardNumber)))"
        }
    }

    private var notificationText: String {
        switch notificationStatus {
        case .authorized?: return "Allowed"
        case .denied?: return "Denied"
        case .provisional?: return "Provisional"
        case .ephemeral?: return "Ephemeral"
        case .notDetermined?: return "Not asked yet"
        case nil: return "…"
        @unknown default: return "Unknown"
        }
    }

    private var backgroundRefreshText: String {
        switch backgroundRefreshStatus {
        case .available?: return "Available"
        case .denied?: return "Turned off in Settings"
        case .restricted?: return "Restricted by the system"
        case nil: return "…"
        @unknown default: return "Unknown"
        }
    }

    private func checkRow(_ title: String, ok: Bool, detail: String) -> some View {
        LabeledContent {
            Label(detail, systemImage: ok ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(ok ? Color.green : Color.secondary)
                .labelStyle(.titleAndIcon)
                .multilineTextAlignment(.trailing)
        } label: {
            Text(title)
        }
    }

    private func refreshStatuses() async {
        backgroundRefreshStatus = UIApplication.shared.backgroundRefreshStatus
        notificationStatus = await environment.notificationManager.authorizationStatus()
        if environment.callGuard.isConfigured, !environment.callGuard.hasFetchedLine {
            await environment.callGuard.refreshLine()
        }
        #if DEBUG
        await refreshEvaluations()
        #endif
    }

    // MARK: - Actions

    /// One batch so the fixtures share a single model load and the weights are released afterwards
    /// (`ScanCoordinator.evaluateBatch`), instead of staying resident after a diagnostics run.
    private func runSamples() {
        isRunningSamples = true
        Task {
            let emails = SampleEmails.all
            let verdicts = await environment.scanCoordinator.evaluateBatch(emails)
            sampleResults = zip(emails, verdicts).map { email, verdict in
                SampleResult(id: email.messageID, subject: email.subject, verdict: verdict)
            }
            isRunningSamples = false
            #if DEBUG
            await refreshEvaluations()
            #endif
        }
    }

    /// Posts a test alert for the bundled PayPal phishing sample, classified by the full pipeline. Nothing is
    /// persisted and the notification carries no record id, so tapping it just opens the app; repeated tests
    /// replace the previous notification.
    private func sendTestNotification() {
        Task {
            let status = await environment.notificationManager.authorizationStatus()
            guard status != .denied else {
                testNotificationMessage = "Notifications are turned off for PhishGuard. Enable them in Settings first."
                return
            }
            if status == .notDetermined {
                let granted = await environment.notificationManager.requestAuthorization()
                guard granted else {
                    testNotificationMessage = "Permission was not granted."
                    return
                }
            }
            let email = SampleEmails.paypalPhish
            guard let verdict = await environment.scanCoordinator.evaluateBatch([email]).first else { return }
            environment.notificationManager.postTestAlert(verdict: verdict)
            testNotificationMessage = "Sent a \(verdict.level.displayName.lowercased()) alert for \"\(email.subject)\". It appears as a banner even while PhishGuard is open."
            await refreshStatuses()
        }
    }
}

#if DEBUG
/// One evaluated message in the Diagnostics debug panel. Everything shown here is metadata the coordinator
/// already recorded: no body text, and a signal's evidence text is deliberately not part of the trace.
struct EvaluationTraceRow: View {
    let trace: EvaluationTrace

    /// "link.lookalike_domain(high)" — the signal id and its severity, which is what a dispute about the rule
    /// score actually needs. `Signal.detail` quotes the email and is never recorded.
    static func signalsText(_ signals: [EvaluationTrace.SignalTrace]) -> String {
        guard !signals.isEmpty else { return "no signals" }
        return signals
            .sorted { ($0.severity, $0.weight) > ($1.severity, $1.weight) }
            .map { "\($0.id)(\($0.severity.rawValue))" }
            .joined(separator: ", ")
    }

    /// "rules 0.80 — link.lookalike_domain(high), content.urgency(medium)".
    static func rulesText(_ trace: EvaluationTrace) -> String {
        "rules \(trace.ruleScore.formatted(.number.precision(.fractionLength(2)))) — \(signalsText(trace.signals))"
    }

    /// "Qwen3 4B: 85 phishing · 1240 ms" for a model that answered, "Apple Intelligence: <reason>" otherwise.
    /// A corroborator also says what became of its score — the whole point of the corroboration rule is that a
    /// loud second opinion can be discarded, so the panel has to show that it was.
    static func modelText(_ run: ModelRun) -> String {
        let name = ClassifierDisplay.shortName(forIdentifier: run.identifier)
        guard let score = run.riskScore, let category = run.category else {
            return "\(name): \(run.errorDescription ?? "no answer")"
        }
        var line = "\(name): \(score) \(category.rawValue) · \(Int((run.duration * 1000).rounded())) ms"
        if let status = run.statusDescription { line += " · \(status)" }
        return line
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                RiskBadge(level: trace.level, size: .compact)
                CategoryChip(category: trace.category)
                Spacer()
                if trace.alerted {
                    Text("ALERTED")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.red)
                }
                Text("\(Int((trace.confidence * 100).rounded()))%")
                    .font(.subheadline.monospacedDigit().weight(.semibold))
                    .foregroundStyle(trace.level.color)
            }
            Text(trace.subject.isEmpty ? "(no subject)" : trace.subject)
                .font(.subheadline.weight(.medium))
                .lineLimit(2)
            Text(trace.sender.isEmpty ? "(no sender)" : trace.sender)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Text(Self.rulesText(trace))
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if trace.modelRuns.isEmpty {
                Text("no model was asked")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
            } else {
                ForEach(Array(trace.modelRuns.enumerated()), id: \.offset) { _, run in
                    Text(Self.modelText(run))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text("\(trace.trigger.rawValue) · \(trace.elapsedMilliseconds) ms · "
                 + trace.date.formatted(date: .omitted, time: .standard))
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}
#endif

#Preview {
    NavigationStack {
        DiagnosticsView()
    }
    .environment(AppEnvironment.preview())
}
