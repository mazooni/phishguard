import SwiftUI

/// "Re-check recent email": forget which messages have already been checked and scan the lookback window
/// again, so a detection improvement — or a scan that was interrupted — does not leave earlier mail
/// unexamined forever.
///
/// Confirms first, because a re-check may post notifications for mail the user has already seen. Used by
/// Diagnostics and by Settings → Scanning; it renders as a button row plus, once it has run, a result row.
struct RecheckRecentEmailButton: View {
    @Environment(AppEnvironment.self) private var environment
    @State private var showConfirmation = false
    @State private var isRunning = false
    @State private var resultText: String?

    static let confirmationTitle = "Re-check recent email?"
    static let confirmationMessage = "PhishGuard forgets which emails it has already checked and looks at your "
        + "inbox again, as far back as the look-back window in Settings → Scanning. Emails that still look "
        + "suspicious can be alerted again."

    /// One sentence for the row under the button. Counts, not mail content.
    static func resultText(for summary: ScanCoordinator.RecheckSummary) -> String {
        var text = "Re-checked \(summary.scanned) \(summary.scanned == 1 ? "email" : "emails"), "
            + "flagged \(summary.flagged)."
        if summary.clearedMessages > 0 {
            text += " Cleared \(summary.clearedMessages) earlier \(summary.clearedMessages == 1 ? "check" : "checks")"
                + " across \(summary.clearedAccounts) \(summary.clearedAccounts == 1 ? "account" : "accounts")."
        }
        if summary.cancelled {
            text += " It stopped early."
        } else if summary.deadlineReached {
            text += " More mail is still pending; it is checked in the background."
        }
        if !summary.errors.isEmpty {
            text += " \(summary.errors.count) \(summary.errors.count == 1 ? "error" : "errors"): "
                + summary.errors.joined(separator: "; ")
        }
        return text
    }

    var body: some View {
        Button {
            showConfirmation = true
        } label: {
            if isRunning {
                Label { Text("Re-checking…") } icon: { ProgressView().controlSize(.small) }
            } else {
                Label("Re-check recent email", systemImage: "clock.arrow.circlepath")
            }
        }
        .disabled(isRunning || environment.isScanning)
        .confirmationDialog(Self.confirmationTitle, isPresented: $showConfirmation, titleVisibility: .visible) {
            Button("Re-check") { run() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(Self.confirmationMessage)
        }

        if let resultText {
            Text(resultText)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func run() {
        isRunning = true
        resultText = nil
        Task {
            let summary = await environment.recheckRecentEmail()
            resultText = Self.resultText(for: summary)
            isRunning = false
        }
    }
}
