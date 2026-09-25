import PhishCore
import SwiftUI

/// The call in progress: who is calling, how long it has been going, the risk gauge, what the relay concluded so
/// far and the transcript as it arrives (partials in secondary style). Everything here is in memory for this call
/// only; nothing is persisted.
struct LiveCallCard: View {
    let call: CallGuardCoordinator.LiveCallState
    let connection: CallGuardClient.ConnectionState

    /// How many transcript lines the card shows; the newest are kept.
    static let visibleSegments = 14

    private var level: RiskLevel { call.level }
    private var tint: Color { call.verdict == nil ? .blue : level.color }

    var body: some View {
        Card(tint: tint) {
            header
            if let verdict = call.verdict {
                verdictSection(verdict)
            } else {
                Text(call.status.isEnded ? "The call has ended." : "Listening… nothing suspicious so far.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.top, 10)
            }
            transcript
        }
        .accessibilityElement(children: .contain)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            if let verdict = call.verdict {
                ConfidenceGauge(confidence: verdict.confidence, level: verdict.level, diameter: 88, lineWidth: 7)
            } else {
                Image(systemName: "phone.badge.waveform")
                    .font(.system(size: 36))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.blue)
                    .frame(width: 88, height: 88)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(connection.color)
                        .frame(width: 8, height: 8)
                        .accessibilityHidden(true)
                    Text(call.status.isEnded ? "Call ended" : "Call in progress")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TimelineView(.periodic(from: call.startedAt, by: 1)) { context in
                        Text(CallDurationFormat.elapsed(since: call.startedAt, now: context.date))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                Text(PhoneNumberFormat.display(call.callerNumber))
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                HStack(spacing: 6) {
                    if let verdict = call.verdict {
                        RiskBadge(level: verdict.level, size: .compact)
                        CategoryChip(category: verdict.category)
                    } else {
                        Text(call.status.displayName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if call.alerted {
                        Label("Alerted", systemImage: "bell.badge.fill")
                            .labelStyle(.titleAndIcon)
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.red)
                    }
                }
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            }
            // The column takes every point the gauge leaves; a trailing `Spacer` would split that width with it
            // and wrap the chips letter by letter on a 402 pt screen.
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func verdictSection(_ verdict: CallVerdict) -> some View {
        if !verdict.summary.isEmpty {
            Text(verdict.summary)
                .font(.subheadline)
                .padding(.top, 10)
                .fixedSize(horizontal: false, vertical: true)
        }
        let reasons = verdict.reasons.prefix(4)
        if !reasons.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(reasons)) { reason in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: reason.severity.symbolName)
                            .font(.caption)
                            .foregroundStyle(reason.severity.color)
                            .accessibilityHidden(true)
                        Text(reason.title)
                            .font(.footnote)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(.top, 8)
        }
        if !verdict.recommendedAction.isEmpty, verdict.level != .safe {
            Label(verdict.recommendedAction, systemImage: "hand.raised.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(verdict.level.color)
                .padding(.top, 8)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var transcript: some View {
        let lines = Array(call.segments.suffix(Self.visibleSegments))
        if !lines.isEmpty {
            Divider()
                .padding(.vertical, 10)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(lines) { segment in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(segment.speaker.label)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(segment.speaker.color)
                            .frame(width: 48, alignment: .leading)
                        Text(segment.text)
                            .font(.subheadline)
                            .italic(!segment.isFinal)
                            .foregroundStyle(segment.isFinal ? .primary : .secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(segment.speaker.label): \(segment.text)\(segment.isFinal ? "" : " (still transcribing)")")
                }
            }
        }
    }
}

#Preview {
    var call = CallGuardCoordinator.LiveCallState(summary: CallSummary(
        callID: UUID().uuidString, source: .twilio, callerNumber: "+14155550134", calledNumber: DemoCalls.guardNumber,
        startedAt: Int(Date().addingTimeInterval(-95).timeIntervalSince1970 * 1000), status: .inProgress,
        verdict: DemoCalls.grandparent.verdict, alerted: true
    ))
    call.merge(TranscriptSegment(id: "1", speaker: .caller, text: "Grandma, it's me. I'm in trouble and I need your help.", atMs: 4000, isFinal: true))
    call.merge(TranscriptSegment(id: "2", speaker: .user, text: "Oh no, what happened?", atMs: 9000, isFinal: true))
    call.merge(TranscriptSegment(id: "3", speaker: .caller, text: "They only take gift cards, you have to", atMs: 14000, isFinal: false))
    return ScrollView {
        LiveCallCard(call: call, connection: .connected)
            .padding()
    }
    .background(Color(.systemGroupedBackground))
}
