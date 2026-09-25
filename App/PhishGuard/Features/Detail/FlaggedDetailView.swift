import PhishCore
import SwiftData
import SwiftUI

/// Verdict details for one flagged email. No body is available (it was never stored).
struct FlaggedDetailView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.modelContext) private var modelContext
    @Environment(\.dismiss) private var dismiss
    let record: FlaggedEmailRecord
    @State private var showOpenWarning = false
    @State private var showDeleteConfirmation = false

    private var subject: String {
        record.subject.isEmpty ? "(no subject)" : record.subject
    }

    private var providerName: String {
        switch record.provider {
        case .gmail?: return "Gmail"
        case .microsoft?: return "Outlook"
        case .imap?: return "your mail app"
        case nil: return "your mail provider"
        }
    }

    private var sortedReasons: [Reason] {
        record.reasons.sorted { $0.severity > $1.severity }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                verdictCard
                summaryCard
                reasonsSection
                senderCard
                if record.webLink != nil {
                    openButton
                }
                footnote
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Flagged email")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button {
                        record.isRead.toggle()
                        if record.isRead {
                            environment.notificationManager.clearAlert(recordID: record.id)
                        }
                    } label: {
                        Label(record.isRead ? "Mark as unread" : "Mark as read", systemImage: record.isRead ? "envelope.badge" : "envelope.open")
                    }
                    ShareLink(item: diagnosticsText, subject: Text("PhishGuard alert diagnostics")) {
                        Label("Share diagnostics", systemImage: "square.and.arrow.up")
                    }
                    Divider()
                    Button(role: .destructive) {
                        showDeleteConfirmation = true
                    } label: {
                        Label("Delete alert", systemImage: "trash")
                    }
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
            }
        }
        .confirmationDialog("Delete this alert?", isPresented: $showDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete alert", role: .destructive) { deleteRecord() }
        } message: {
            Text("Only PhishGuard's record is removed. The email itself stays in your mailbox.")
        }
        .sheet(isPresented: $showOpenWarning) {
            if let link = record.webLink {
                OpenInProviderSheet(link: link, providerName: providerName)
                    .presentationDetents([.medium])
                    .presentationDragIndicator(.visible)
            }
        }
        .onAppear {
            if !record.isRead {
                record.isRead = true // HomeView observes the unread set and lowers the icon badge accordingly
            }
            environment.notificationManager.clearAlert(recordID: record.id)
        }
    }

    // MARK: - Sections

    private var verdictCard: some View {
        Card(tint: record.level.color) {
            HStack(alignment: .center, spacing: 16) {
                ConfidenceGauge(confidence: record.confidence, level: record.level, diameter: 108, lineWidth: 10)
                VStack(alignment: .leading, spacing: 8) {
                    RiskBadge(level: record.level)
                    CategoryChip(category: record.category)
                    Text(subject)
                        .font(.headline)
                        .lineLimit(4)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
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
                Text("No detailed reasons were recorded for this email.")
                    .foregroundStyle(.secondary)
            }
        } else {
            ForEach(reasons) { reason in
                ReasonCard(reason: reason)
            }
        }
    }

    private var senderCard: some View {
        Card {
            CardTitle(title: "Sender", systemImage: "person.crop.circle")
            VStack(alignment: .leading, spacing: 10) {
                if let name = record.senderName, !name.isEmpty {
                    detailRow("Name", name)
                }
                detailRow("Address", record.senderAddress.isEmpty ? "(unknown)" : record.senderAddress)
                detailRow("Received", record.receivedAt.formatted(date: .long, time: .shortened))
                if let provider = record.provider {
                    detailRow("Account", provider.displayName)
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

    private var openButton: some View {
        Button {
            showOpenWarning = true
        } label: {
            Label("Open in \(providerName)", systemImage: "arrow.up.right.square")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
        .accessibilityHint("Shows a safety warning before opening the email in \(providerName).")
    }

    private var footnote: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(ClassifierDisplay.footnote(forIdentifier: record.modelIdentifier))
            Text("Flagged \(record.flaggedAt.formatted(date: .abbreviated, time: .shortened)).")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.top, 4)
    }

    // MARK: - Diagnostics text (metadata + verdict only; no message body exists to share)

    private var diagnosticsText: String {
        var lines: [String] = []
        lines.append("PhishGuard alert diagnostics")
        lines.append("Level: \(record.level.displayName) (\(Int((record.confidence * 100).rounded()))% confidence)")
        lines.append("Category: \(record.category.displayName)")
        lines.append("Subject: \(subject)")
        lines.append("From: \(record.senderDisplay)")
        lines.append("Received: \(record.receivedAt.formatted(date: .abbreviated, time: .shortened))")
        lines.append("Flagged: \(record.flaggedAt.formatted(date: .abbreviated, time: .shortened))")
        lines.append("Provider: \(record.provider?.displayName ?? record.providerRaw)")
        lines.append("Model: \(ClassifierDisplay.name(forIdentifier: record.modelIdentifier))")
        lines.append("Summary: \(record.summary)")
        lines.append("Reasons:")
        for reason in sortedReasons {
            lines.append("- [\(reason.severity.rawValue)/\(reason.source.rawValue)] \(reason.title): \(reason.detail)")
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - Actions

    private func deleteRecord() {
        environment.notificationManager.clearAlert(recordID: record.id)
        modelContext.delete(record)
        try? modelContext.save()
        dismiss()
    }
}

/// One "why it was flagged" card: severity icon, title, detail and Heuristic/AI source tag.
private struct ReasonCard: View {
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
                    Text(reason.detail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("\(reason.severity.displayName) severity")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// Warning shown before handing off to the provider's web UI.
private struct OpenInProviderSheet: View {
    @Environment(\.dismiss) private var dismiss
    let link: URL
    let providerName: String

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("Open carefully")
                .font(.title2.bold())
            Text("Don't click links or open attachments in this email. If it asks for a password, a code or a payment, treat it as fraudulent and delete it.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Link(destination: link) {
                Label("Open in \(providerName)", systemImage: "arrow.up.right.square")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            Button("Cancel") { dismiss() }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
        }
        .padding(24)
    }
}

#Preview {
    let environment = AppEnvironment.preview()
    DemoData.seed(into: environment.container)
    let records = (try? environment.container.mainContext.fetch(FetchDescriptor<FlaggedEmailRecord>())) ?? []
    return NavigationStack {
        if let record = records.first {
            FlaggedDetailView(record: record)
        } else {
            Text("No demo record")
        }
    }
    .environment(environment)
    .modelContainer(environment.container)
}
