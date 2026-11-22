import PhishCore
import SwiftData
import SwiftUI

/// Verdict details for one flagged call. There is no transcript here — it was never stored. When the relay's
/// AI-voice check judged the caller's voice synthetic, that has a card of its own: it is not part of the verdict.
struct CallDetailView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.modelContext) private var modelContext
    @Environment(\.dismiss) private var dismiss
    let record: FlaggedCallRecord
    @State private var showDeleteConfirmation = false

    private var caller: String { PhoneNumberFormat.display(record.callerNumber) }

    private var sortedReasons: [Reason] {
        record.reasons.sorted { $0.severity > $1.severity }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                verdictCard
                voiceCard
                if !record.isVoiceOnly {
                    summaryCard
                }
                reasonsSection
                actionCard
                factsCard
                footnote
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Flagged call")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button {
                        record.isRead.toggle()
                        if record.isRead {
                            environment.notificationManager.clearCallAlert(callID: record.id)
                        }
                    } label: {
                        Label(record.isRead ? "Mark as unread" : "Mark as read", systemImage: record.isRead ? "phone.badge.checkmark" : "phone.arrow.down.left")
                    }
                    ShareLink(item: diagnosticsText, subject: Text("PhishGuard call diagnostics")) {
                        Label("Share diagnostics", systemImage: "square.and.arrow.up")
                    }
                    Divider()
                    Button(role: .destructive) {
                        showDeleteConfirmation = true
                    } label: {
                        Label("Delete call", systemImage: "trash")
                    }
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
            }
        }
        .confirmationDialog("Delete this call?", isPresented: $showDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete call", role: .destructive) { deleteRecord() }
        } message: {
            Text("Only PhishGuard's record of the call is removed.")
        }
        .onAppear {
            if !record.isRead {
                record.isRead = true // the Calls tab badge observes the unread set
            }
            environment.notificationManager.clearCallAlert(callID: record.id)
        }
    }

    // MARK: - Sections

    /// The scam verdict — except on a call listed only because of the caller's voice, where a green "Safe" gauge
    /// and badge beside "You were warned during the call" would contradict the warning: there the voice finding
    /// stands in its place.
    @ViewBuilder
    private var verdictCard: some View {
        if record.isVoiceOnly {
            voiceOnlyHeader
        } else {
            scamVerdictCard
        }
    }

    private var voiceOnlyHeader: some View {
        Card(tint: VoiceStatus.synthetic.color) {
            HStack(alignment: .center, spacing: 16) {
                Image(systemName: VoiceStatus.synthetic.symbolName)
                    .font(.system(size: 44, weight: .semibold))
                    .foregroundStyle(VoiceStatus.synthetic.color)
                    .frame(width: 108, height: 108)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 8) {
                    CallVoiceBadge()
                    Text(caller)
                        .font(.headline)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(record.hasNoScamVerdict ? CallVoiceDisplay.noScamVerdict : CallVoiceDisplay.noScamSigns)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if record.alerted {
                        Label("You were warned during the call", systemImage: "bell.badge.fill")
                            .font(.caption)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private var scamVerdictCard: some View {
        Card(tint: record.level.color) {
            HStack(alignment: .center, spacing: 16) {
                ConfidenceGauge(confidence: record.confidence, level: record.level, diameter: 108, lineWidth: 10)
                VStack(alignment: .leading, spacing: 8) {
                    RiskBadge(level: record.level)
                    CategoryChip(category: record.category)
                    Text(caller)
                        .font(.headline)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                    if record.alerted {
                        Label("You were warned during the call", systemImage: "bell.badge.fill")
                            .font(.caption)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    /// Only for a voice judged AI-generated. Whether the warning was spoken or pushed is not stored, so it is
    /// not shown; "You were warned during the call" on the verdict card covers both kinds of warning.
    @ViewBuilder
    private var voiceCard: some View {
        if let status = record.voiceStatus, status == .synthetic {
            Card(tint: status.color) {
                CardTitle(title: CallVoiceDisplay.detectedTitle, systemImage: status.symbolName, tint: status.color)
                Text(CallVoiceDisplay.explanation)
                    .font(.body)
                    .padding(.top, 6)
                    .fixedSize(horizontal: false, vertical: true)
                if let measurement = CallVoiceDisplay.measurement(share: record.voiceSyntheticShare, confidence: record.voiceConfidence) {
                    Text(measurement)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.top, 6)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityElement(children: .combine)
        }
    }

    private var summaryCard: some View {
        Card {
            CardTitle(title: "Summary", systemImage: "text.alignleft")
            Text(record.summary.isEmpty ? "No summary was recorded." : record.summary)
                .font(.body)
                .padding(.top, 6)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var reasonsSection: some View {
        Text("Why it was flagged")
            .font(.title3.bold())
            .padding(.top, 4)
            .accessibilityAddTraits(.isHeader)
        let reasons = sortedReasons
        if reasons.isEmpty {
            Card {
                Text(record.voiceStatus == .synthetic && record.level == .safe
                     ? CallVoiceDisplay.listedForVoiceOnly
                     : "No detailed reasons were recorded for this call.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else {
            ForEach(reasons) { reason in
                CallReasonCard(reason: reason)
            }
        }
    }

    @ViewBuilder
    private var actionCard: some View {
        // Not on a voice-only call: its verdict's advice is "Nothing suspicious so far.", under an AI-voice warning.
        if !record.recommendedAction.isEmpty, !record.isVoiceOnly {
            Card(tint: record.level.color) {
                CardTitle(title: "What to do", systemImage: "hand.raised.fill", tint: record.level.color)
                Text(record.recommendedAction)
                    .font(.body.weight(.semibold))
                    .padding(.top, 6)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var factsCard: some View {
        Card {
            CardTitle(title: "Call", systemImage: "phone")
            VStack(alignment: .leading, spacing: 10) {
                detailRow("Caller", caller)
                detailRow("When", record.startedAt.formatted(date: .long, time: .shortened))
                if let duration = record.durationSeconds {
                    detailRow("Duration", CallDurationFormat.string(seconds: duration))
                } else if let status = record.status {
                    detailRow("Status", status.displayName)
                }
                detailRow("Source", record.source?.displayName ?? record.sourceRaw)
                if !record.guardNumber.isEmpty {
                    detailRow("Guard number", PhoneNumberFormat.display(record.guardNumber))
                }
                if record.voiceStatus == .human {
                    detailRow("Caller's voice", CallVoiceDisplay.humanFact)
                }
            }
            .padding(.top, 8)
        }
    }

    private func detailRow(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var footnote: some View {
        VStack(alignment: .leading, spacing: 4) {
            if !record.hasNoScamVerdict {
                Text(CallModelDisplay.footnote(forIdentifier: record.modelIdentifier))
            }
            if let voiceFootnote = CallVoiceDisplay.footnote(status: record.voiceStatus, provider: record.voiceProvider) {
                Text(voiceFootnote)
            }
            if record.isDemo {
                Text("A demo call from a bundled scenario; nothing was transcribed or sent anywhere.")
            }
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.top, 4)
    }

    // MARK: - Diagnostics text (numbers, times and the verdict only; no transcript exists to share)

    private var diagnosticsText: String {
        var lines: [String] = []
        lines.append("PhishGuard call diagnostics")
        lines.append("Level: \(record.level.displayName) (\(Int((record.confidence * 100).rounded()))% confidence)")
        lines.append("Category: \(record.category.displayName)")
        lines.append("Caller: \(record.callerNumber)")
        lines.append("Guard number: \(record.guardNumber)")
        lines.append("Started: \(record.startedAt.formatted(date: .abbreviated, time: .shortened))")
        if let duration = record.durationSeconds {
            lines.append("Duration: \(CallDurationFormat.string(seconds: duration))")
        }
        lines.append("Status: \(record.status?.displayName ?? record.statusRaw)")
        lines.append("Source: \(record.source?.displayName ?? record.sourceRaw)")
        lines.append("Alerted: \(record.alerted ? "yes" : "no")")
        lines.append("Model: \(CallModelDisplay.name(forIdentifier: record.modelIdentifier))")
        if let voiceLine = CallVoiceDisplay.diagnostics(
            statusRaw: record.voiceStatusRaw, share: record.voiceSyntheticShare, confidence: record.voiceConfidence, provider: record.voiceProvider
        ) {
            lines.append(voiceLine)
        }
        lines.append("Summary: \(record.summary)")
        lines.append("Recommended: \(record.recommendedAction)")
        lines.append("Reasons:")
        for reason in sortedReasons {
            lines.append("- [\(reason.severity.rawValue)/\(reason.source.rawValue)] \(reason.title): \(reason.detail)")
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - Actions

    private func deleteRecord() {
        environment.notificationManager.clearCallAlert(callID: record.id)
        modelContext.delete(record)
        try? modelContext.save()
        dismiss()
    }
}

/// One "why it was flagged" card: severity icon, title, detail and the Heuristic/AI source tag.
private struct CallReasonCard: View {
    let reason: Reason

    var body: some View {
        Card(tint: reason.severity == .info ? nil : reason.severity.color) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: reason.severity.symbolName)
                    .font(.title3)
                    .foregroundStyle(reason.severity.color)
                    .frame(width: 28)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(reason.title)
                            .font(.headline)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 8)
                        SourceTag(source: reason.source)
                    }
                    if !reason.detail.isEmpty {
                        Text(reason.detail)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text("\(reason.severity.displayName) severity")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    let environment = AppEnvironment.preview()
    let record = DemoCalls.makeRecord(DemoCalls.grandparent, startedAt: .now, isDemo: true)
    environment.container.mainContext.insert(record)
    return NavigationStack {
        CallDetailView(record: record)
    }
    .environment(environment)
    .modelContainer(environment.container)
}
