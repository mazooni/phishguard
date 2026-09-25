import PhishCore
import SwiftData
import SwiftUI
import UserNotifications

/// Flagged emails newest first, grouped by day and filtered by the minimum alert level, with a status header,
/// pull-to-refresh / "Scan now" and notification deep links (`AppEnvironment.pendingRecordID`).
struct HomeView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.modelContext) private var modelContext
    @Environment(\.scenePhase) private var scenePhase
    @Query(sort: \FlaggedEmailRecord.receivedAt, order: .reverse) private var records: [FlaggedEmailRecord]
    /// Drives the app-icon badge: every read/unread toggle, delete and account removal changes this set.
    @Query(filter: #Predicate<FlaggedEmailRecord> { !$0.isRead }) private var unread: [FlaggedEmailRecord]
    /// Real mailboxes only. The Demo-mode account has no mailbox behind it and is never scanned, so counting it
    /// in the shield status or in the "Accounts" figure would claim a watched mailbox that does not exist.
    @Query(filter: #Predicate<LinkedAccount> { !$0.isDemo }) private var accounts: [LinkedAccount]
    @State private var path: [UUID] = []
    @State private var notificationsAuthorized: Bool?
    /// The Detection model screen, reached from the "model not downloaded" banner. A sheet rather than a push:
    /// `path` is typed `[UUID]` for record deep links, and that is the only thing that belongs on it.
    @State private var isShowingModelSettings = false

    /// Square box the toolbar glyph and the scanning spinner are both centred in, so swapping one for the other
    /// cannot move the icon inside the bar's circular background. The bar pads it out to the 44 pt tap target.
    private static let scanGlyphBox: CGFloat = 24

    private var visibleRecords: [FlaggedEmailRecord] {
        AlertFilter.filter(records, minimum: environment.settings.alertMinimumLevel, level: \.level)
    }

    private var sections: [DaySection<FlaggedEmailRecord>] {
        DayGrouping.sections(visibleRecords, date: \.receivedAt)
    }

    private var hiddenCount: Int { records.count - visibleRecords.count }

    private var shieldStatus: ShieldStatus {
        .make(enabledAccountCount: accounts.filter(\.isEnabled).count, notificationsAuthorized: notificationsAuthorized)
    }

    /// The local model is the default classifier, but onboarding can be skipped and older installs never had the
    /// download page. Until the model is on disk the scans below silently run heuristics only, so say so.
    private var needsModelDownload: Bool {
        ModelReadiness.showsMissingModelBanner(
            choice: environment.settings.classifierChoice,
            isModelDownloaded: environment.classifierRegistry.effectiveMLXModelID != nil
        )
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                if needsModelDownload {
                    Section {
                        modelDownloadBanner
                    }
                    .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
                    .listRowBackground(Color.clear)
                }

                Section {
                    headerCard
                }
                .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
                .listRowBackground(Color.clear)

                if visibleRecords.isEmpty {
                    Section {
                        emptyState
                    }
                    .listRowBackground(Color.clear)
                } else {
                    ForEach(sections) { section in
                        Section(section.title) {
                            ForEach(section.items) { record in
                                NavigationLink(value: record.id) {
                                    FlaggedRow(record: record)
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
                                            environment.notificationManager.clearAlert(recordID: record.id)
                                        }
                                    } label: {
                                        Label(record.isRead ? "Mark unread" : "Mark read", systemImage: record.isRead ? "envelope.badge" : "envelope.open")
                                    }
                                    .tint(.blue)
                                }
                            }
                        }
                    }
                    if hiddenCount > 0 {
                        Section {
                            Text("\(hiddenCount) lower-risk \(hiddenCount == 1 ? "email is" : "emails are") hidden by your alert level. Change it in Settings → Alerts.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        .listRowBackground(Color.clear)
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("PhishGuard")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    scanButton
                }
            }
            .refreshable {
                await environment.runScan(trigger: .manual)
            }
            .navigationDestination(for: UUID.self) { id in
                FlaggedRecordDestination(recordID: id)
            }
            .sheet(isPresented: $isShowingModelSettings) {
                NavigationStack {
                    ModelSettingsView()
                        .toolbar {
                            ToolbarItem(placement: .confirmationAction) {
                                Button("Done") { isShowingModelSettings = false }
                            }
                        }
                }
            }
            .task {
                await refreshNotificationStatus()
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    Task { await refreshNotificationStatus() }
                }
            }
            .onChange(of: environment.pendingRecordID, initial: true) { _, pending in
                guard let pending else { return }
                path = [pending]
                environment.pendingRecordID = nil
            }
            // The scan pipeline sets the icon badge to the unread flagged count with each alert; keep it in sync
            // with the store here (including on appearance, which also clears a badge left by a background scan).
            .onChange(of: unread.count, initial: true) { _, count in
                environment.notificationManager.setBadge(unreadCount: count)
            }
        }
    }

    // MARK: - Pieces

    /// Toolbar "Scan now", inside the bar's circular background.
    ///
    /// Two things used to pull the glyph off that circle's centre: the label swapped between a `Label` and a
    /// `ProgressView` of a different size while scanning, so the bar re-laid the item out mid-scan; and the
    /// symbol was centred on its layout box while its ink is not centred inside it. Both states now sit in one
    /// fixed square box (so the swap cannot move anything) and the symbol is `arrow.triangle.2.circlepath`,
    /// whose ink is centred on that box — `arrow.clockwise` hangs its arrowhead above and outside the ring, which
    /// left the ring itself low and to the left. Verified from a screenshot, not by eye: on the iPhone 17 Pro
    /// Simulator the bar's circular background measures 132×132 device px (44 pt) and the glyph's ink bounding box
    /// sits 0.5 px (0.17 pt) off its centre; forcing the scanning branch puts the spinner's 42×42 px box exactly on
    /// the same centre, so the swap moves nothing. See docs/screenshots/home.png. It is also the only circular
    /// control on this screen — the empty-state "Scan now" and the banner below are pill/card shaped — so nothing
    /// else needed the same treatment.
    private var scanButton: some View {
        Button {
            Task { await environment.runScan(trigger: .manual) }
        } label: {
            ZStack {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .opacity(environment.isScanning ? 0 : 1)
                ProgressView()
                    .controlSize(.small)
                    .opacity(environment.isScanning ? 1 : 0)
            }
            .font(.body)
            .frame(width: Self.scanGlyphBox, height: Self.scanGlyphBox)
            .contentShape(.rect)
        }
        .disabled(environment.isScanning)
        .accessibilityLabel(environment.isScanning ? "Scanning" : "Scan now")
    }

    /// Tapping opens the Detection model screen, where the download lives.
    private var modelDownloadBanner: some View {
        Button {
            isShowingModelSettings = true
        } label: {
            Card(tint: .orange) {
                HStack(spacing: 12) {
                    Image(systemName: "arrow.down.circle")
                        .font(.title2)
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Detection model not downloaded")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.primary)
                        Text("Tap to download it. Until then new email is checked without it.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 4)
                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Opens the Detection model settings.")
    }

    private var headerCard: some View {
        let status = shieldStatus
        return Card(tint: status.color) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: status.symbolName)
                    .font(.system(size: 36))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(status.color)
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
            Divider()
                .padding(.vertical, 10)
            HStack(alignment: .top) {
                stat("Last scan", lastScanText, systemImage: "clock")
                Spacer()
                stat("Accounts", "\(accounts.count)", systemImage: "person.crop.circle")
                Spacer()
                stat("Flagged", "\(records.count)", systemImage: "flag")
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var lastScanText: String {
        if environment.isScanning { return "Scanning…" }
        guard let date = environment.lastScanDate else { return "Never" }
        return date.formatted(.relative(presentation: .named))
    }

    private func stat(_ title: String, _ value: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline.weight(.semibold))
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No suspicious emails", systemImage: "checkmark.shield")
        } description: {
            Text(records.isEmpty
                 ? "PhishGuard checks new mail in the background and lists anything that looks like phishing or a scam here."
                 : "Nothing at or above your alert level. Lower-risk emails are hidden.")
        } actions: {
            Button {
                Task { await environment.runScan(trigger: .manual) }
            } label: {
                Label("Scan now", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .disabled(environment.isScanning)
        }
    }

    // MARK: - Actions

    private func delete(_ record: FlaggedEmailRecord) {
        environment.notificationManager.clearAlert(recordID: record.id)
        modelContext.delete(record)
        try? modelContext.save()
    }

    private func refreshNotificationStatus() async {
        let status = await environment.notificationManager.authorizationStatus()
        switch status {
        case .authorized, .provisional, .ephemeral:
            notificationsAuthorized = true
        case .denied:
            notificationsAuthorized = false
        case .notDetermined:
            notificationsAuthorized = false
        @unknown default:
            notificationsAuthorized = nil
        }
    }
}

/// Row: unread dot, compact risk badge, sender, subject and relative time.
struct FlaggedRow: View {
    let record: FlaggedEmailRecord

    private var sender: String {
        if let name = record.senderName, !name.isEmpty { return name }
        return record.senderAddress
    }

    private var subject: String {
        record.subject.isEmpty ? "(no subject)" : record.subject
    }

    private var relativeTime: String {
        record.receivedAt.formatted(.relative(presentation: .named))
    }

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
                    Text(sender)
                        .font(.subheadline.weight(record.isRead ? .regular : .semibold))
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    Text(relativeTime)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Text(subject)
                    .font(.body)
                    .foregroundStyle(record.isRead ? .secondary : .primary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(record.isRead ? "" : "Unread. ")\(record.level.displayName), from \(sender): \(subject), \(relativeTime)")
    }
}

/// Resolves a record id pushed on the navigation path (rows and notification deep links).
struct FlaggedRecordDestination: View {
    @Query private var matches: [FlaggedEmailRecord]

    init(recordID: UUID) {
        _matches = Query(filter: #Predicate<FlaggedEmailRecord> { $0.id == recordID })
    }

    var body: some View {
        if let record = matches.first {
            FlaggedDetailView(record: record)
        } else {
            ContentUnavailableView("Alert removed", systemImage: "trash", description: Text("This alert is no longer available."))
                .navigationTitle("Flagged email")
                .navigationBarTitleDisplayMode(.inline)
        }
    }
}

#Preview("With alerts") {
    let environment = AppEnvironment.preview()
    DemoData.seed(into: environment.container)
    return HomeView()
        .environment(environment)
        .modelContainer(environment.container)
}

#Preview("Empty") {
    let environment = AppEnvironment.preview()
    return HomeView()
        .environment(environment)
        .modelContainer(environment.container)
}
