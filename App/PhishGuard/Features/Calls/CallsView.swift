import PhishCore
import SwiftData
import SwiftUI
import UIKit
import UserNotifications

/// The Calls tab: the protection status (with the guard number to hand out), the call in progress as the live
/// feed reports it, and the flagged calls grouped by day. Pull to refresh re-reads the relay's history; the live
/// feed runs while this tab is on screen and the app is active.
struct CallsView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.modelContext) private var modelContext
    @Environment(\.scenePhase) private var scenePhase
    @Query(sort: \FlaggedCallRecord.startedAt, order: .reverse) private var records: [FlaggedCallRecord]
    @State private var path: [UUID] = []
    @State private var isShowingSetup = false
    /// True between `onAppear` and `onDisappear`, so a scene activation on another tab does not open the feed.
    @State private var isVisible = false
    /// One line of feedback under the cards ("Scripted call started…", an error).
    @State private var actionMessage: String?
    /// nil until read; a protected line whose notifications are off cannot warn anyone while the app is closed.
    @State private var notificationStatus: UNAuthorizationStatus?

    private var coordinator: CallGuardCoordinator { environment.callGuard }

    private var sections: [DaySection<FlaggedCallRecord>] {
        DayGrouping.sections(records, date: \.startedAt)
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    if coordinator.isConfigured, !coordinator.hasFetchedLine {
                        loadingCard
                    } else {
                        statusCard
                    }
                }
                .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
                .listRowBackground(Color.clear)

                if let call = coordinator.activeCall {
                    Section {
                        LiveCallCard(call: call, connection: coordinator.connection)
                    }
                    .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
                    .listRowBackground(Color.clear)
                }

                if let actionMessage {
                    Section {
                        Text(actionMessage)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .listRowBackground(Color.clear)
                }

                if records.isEmpty {
                    Section {
                        emptyState
                    }
                    .listRowBackground(Color.clear)
                } else {
                    ForEach(sections) { section in
                        Section(section.title) {
                            ForEach(section.items) { record in
                                NavigationLink(value: record.id) {
                                    CallRow(record: record)
                                }
                                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                    Button(role: .destructive) {
                                        delete(record)
                                    } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                                .swipeActions(edge: .leading) {
                                    Button {
                                        record.isRead.toggle()
                                        if record.isRead {
                                            environment.notificationManager.clearCallAlert(callID: record.id)
                                        }
                                    } label: {
                                        Label(record.isRead ? "Mark unread" : "Mark read", systemImage: record.isRead ? "phone.badge.checkmark" : "phone.arrow.down.left")
                                    }
                                    .tint(.blue)
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Calls")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    toolbarMenu
                }
            }
            .refreshable {
                await coordinator.refreshAll()
            }
            .navigationDestination(for: UUID.self) { id in
                CallRecordDestination(callID: id)
            }
            .sheet(isPresented: $isShowingSetup) {
                CallSetupView(
                    line: coordinator.line,
                    phoneNumber: environment.settings.protectedPhoneNumber,
                    minimumLevel: environment.settings.callAlertMinimumLevel,
                    spokenWarning: environment.settings.callSpokenWarningEnabled
                )
            }
            .onAppear {
                isVisible = true
                coordinator.startLive()
                Task { await coordinator.refreshAll() }
                Task { notificationStatus = await environment.notificationManager.authorizationStatus() }
            }
            .onDisappear {
                isVisible = false
                coordinator.stopLive()
            }
            .onChange(of: scenePhase) { _, phase in
                guard isVisible else { return }
                if phase == .active {
                    coordinator.startLive()
                    Task { await coordinator.refreshHistory() }
                    Task { notificationStatus = await environment.notificationManager.authorizationStatus() }
                } else {
                    coordinator.stopLive()
                }
            }
            .onChange(of: coordinator.pendingCallID, initial: true) { _, pending in
                guard let pending else { return }
                path = [pending]
                coordinator.pendingCallID = nil
            }
        }
    }

    // MARK: - Pieces

    private var toolbarMenu: some View {
        Menu {
            Button {
                isShowingSetup = true
            } label: {
                Label(coordinator.line == nil ? "Set up call protection" : "Call protection settings", systemImage: "phone.badge.checkmark")
            }
            .disabled(!coordinator.isConfigured)
            if coordinator.isConfigured {
                Divider()
                Menu {
                    ForEach(DemoScenario.allCases) { scenario in
                        Button(scenario.displayName) { startDemoCall(scenario) }
                    }
                } label: {
                    Label("Run a scripted call on the relay", systemImage: "waveform")
                }
                Menu {
                    ForEach(DemoScenario.allCases) { scenario in
                        Button(scenario.displayName) { startTestCall(scenario) }
                    }
                } label: {
                    Label("Place a test call to my phone", systemImage: "phone.arrow.up.right")
                }
                .disabled(coordinator.line == nil)
            }
        } label: {
            Label("More", systemImage: "ellipsis.circle")
        }
    }

    private var loadingCard: some View {
        Card {
            HStack(spacing: 12) {
                ProgressView()
                Text("Checking call protection…")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var statusCard: some View {
        let status = coordinator.status
        return Card(tint: status.isProtected ? .green : .orange) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: status.symbolName)
                    .font(.system(size: 36))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(status.isProtected ? .green : .orange)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(status.title)
                        .font(.title3.weight(.semibold))
                    Text(status.detail)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            switch status {
            case .protected(let guardNumber, let phoneNumber):
                Divider()
                    .padding(.vertical, 10)
                HStack(alignment: .top) {
                    stat("Guard number", PhoneNumberFormat.display(guardNumber), systemImage: "phone.fill")
                    Spacer()
                    Button {
                        UIPasteboard.general.string = guardNumber
                        actionMessage = "Guard number copied."
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                HStack(alignment: .top) {
                    stat("Rings", PhoneNumberFormat.display(phoneNumber), systemImage: "iphone")
                    Spacer()
                    Label(coordinator.connection.label, systemImage: "dot.radiowaves.left.and.right")
                        .font(.caption)
                        .foregroundStyle(coordinator.connection.color)
                }
                .padding(.top, 8)
                notificationsRow
            case .notSetUp:
                Button {
                    isShowingSetup = true
                } label: {
                    Label("Set up call protection", systemImage: "phone.badge.checkmark")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 12)
            case .relayNotConfigured:
                EmptyView()
            }
            if let error = coordinator.lastError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.top, 8)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The banner is the product: say plainly when iOS will not show one, and offer the two ways to fix it.
    @ViewBuilder
    private var notificationsRow: some View {
        switch notificationStatus {
        case .denied?:
            VStack(alignment: .leading, spacing: 8) {
                Label("Notifications are off, so no alert can appear while the app is closed.", systemImage: "bell.slash")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                if let url = URL(string: UIApplication.openNotificationSettingsURLString) {
                    Link(destination: url) {
                        Label("Turn on notifications in Settings", systemImage: "gear")
                    }
                    .font(.footnote.weight(.semibold))
                }
            }
            .padding(.top, 10)
        case .notDetermined?:
            VStack(alignment: .leading, spacing: 8) {
                Label("Notifications have not been allowed yet; a scam call could not alert you.", systemImage: "bell.badge")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Button {
                    Task {
                        _ = await environment.notificationManager.requestAuthorization()
                        notificationStatus = await environment.notificationManager.authorizationStatus()
                    }
                } label: {
                    Label("Allow notifications", systemImage: "bell")
                }
                .font(.footnote.weight(.semibold))
            }
            .padding(.top, 10)
        default:
            EmptyView()
        }
    }

    private func stat(_ title: String, _ value: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline.weight(.semibold))
                .monospacedDigit()
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No flagged calls", systemImage: "phone.badge.checkmark")
        } description: {
            Text(coordinator.status.isProtected
                 ? "Calls to your guard number are checked while you talk. Anything that looks like a scam is listed here."
                 : "Once call protection is set up, calls that look like scams are listed here.")
        }
    }

    // MARK: - Actions

    private func delete(_ record: FlaggedCallRecord) {
        environment.notificationManager.clearCallAlert(callID: record.id)
        modelContext.delete(record)
        try? modelContext.save()
    }

    private func startDemoCall(_ scenario: DemoScenario) {
        Task {
            do {
                _ = try await coordinator.startDemoCall(scenario: scenario)
                actionMessage = "Scripted \"\(scenario.displayName)\" call started on the relay — it appears above as it plays."
            } catch {
                actionMessage = CallGuardCoordinator.message(for: error)
            }
        }
    }

    private func startTestCall(_ scenario: DemoScenario) {
        Task {
            do {
                _ = try await coordinator.startTestCall(scenario: scenario)
                actionMessage = "Your phone will ring from the guard number with the \"\(scenario.displayName)\" script."
            } catch {
                actionMessage = CallGuardCoordinator.message(for: error)
            }
        }
    }
}

/// Row: unread dot, compact risk badge, caller, relative time, the summary and whether the relay alerted.
struct CallRow: View {
    let record: FlaggedCallRecord

    private var caller: String { PhoneNumberFormat.display(record.callerNumber) }
    private var relativeTime: String { record.startedAt.formatted(.relative(presentation: .named)) }
    private var summary: String { record.summary.isEmpty ? CallAlertText.fallbackBody : record.summary }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(record.isRead ? Color.clear : Color.accentColor)
                .frame(width: 9, height: 9)
                .padding(.top, 5)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    RiskBadge(level: record.level, size: .compact)
                    Text(caller)
                        .font(.subheadline.weight(record.isRead ? .regular : .semibold))
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    Text(relativeTime)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Text(summary)
                    .font(.body)
                    .foregroundStyle(record.isRead ? .secondary : .primary)
                    .lineLimit(2)
                HStack(spacing: 10) {
                    if record.alerted {
                        Label("Alerted", systemImage: "bell.badge.fill")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.red)
                    }
                    if let duration = record.durationSeconds {
                        Label(CallDurationFormat.string(seconds: duration), systemImage: "clock")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    if record.isDemo {
                        Text("Demo")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(record.isRead ? "" : "Unread. ")\(record.level.displayName), call from \(caller): \(summary), \(relativeTime)")
    }
}

/// Resolves a call id pushed on the navigation path (rows and notification deep links).
struct CallRecordDestination: View {
    @Query private var matches: [FlaggedCallRecord]

    init(callID: UUID) {
        _matches = Query(filter: #Predicate<FlaggedCallRecord> { $0.id == callID })
    }

    var body: some View {
        if let record = matches.first {
            CallDetailView(record: record)
        } else {
            ContentUnavailableView("Call removed", systemImage: "trash", description: Text("This call is no longer listed."))
                .navigationTitle("Flagged call")
                .navigationBarTitleDisplayMode(.inline)
        }
    }
}

#Preview("With calls") {
    let environment = AppEnvironment.preview()
    DemoData.seed(into: environment.container)
    return CallsView()
        .environment(environment)
        .modelContainer(environment.container)
}

#Preview("Empty") {
    let environment = AppEnvironment.preview()
    return CallsView()
        .environment(environment)
        .modelContainer(environment.container)
}
