import Foundation
import PhishCore
import SwiftData

/// Bundled scam-call scenarios for the in-app, offline demo (docs/CALLS.md §7.4): Settings › Demo › "Simulate a
/// scam call" turns one into a `FlaggedCallRecord` dated now and posts the same local notification the relay's
/// push produces; `DemoData` and Demo mode seed three of them across the week.
///
/// The verdicts are the relay's rule engine's own output, recorded once and checked in — the "rule engine's
/// recorded verdict" of §7.4, not a reconstruction. Nothing leaves the phone.
///
/// ## Provenance
///
/// - script: `Relay/scripts/export-demo-verdicts.ts` (`cd Relay && npm run calls:export-demo-verdicts`), which feeds
///   each scenario of `Relay/src/calls/demo/scenarios.ts` through `analyzeTranscript` + `fuseVerdict` exactly as
///   `ScamDetector` does for a rules-only call (docs/CALLS.md §6.1–§6.3; no model, so `modelIdentifier` is nil)
/// - rules, fusion and scenarios as of commit `a4b1869` (2026-09-24, "fix(relay): a single-card gift-card errand is no
///   longer an alert …" — the gift-card signal split into `call.gift_cards` / `call.gift_card_errand`; only the two
///   `call.gift_cards` quotes below changed, every id, confidence, summary and sequence is as first recorded)
/// - exported: 2026-09-24
/// - `sequence` is the number of verdicts the detector emitted over the call (its hysteresis: level, confidence to
///   2 dp, reason ids, summary); `updatedAt` is the detector's clock, fixed at 0 by the export; `durationSeconds`
///   is the scripted length rounded up; `title` and `callerNumber` are the relay scenario's
///
/// Re-run the script after any change to `scoring/rules.ts`, `scoring/fusion.ts` or `demo/scenarios.ts` and paste
/// its Swift output here verbatim. Nothing below is hand-written or hand-corrected — where the rules quote an odd
/// fragment or fire on a harmless phrase, that is what is stored, because it is what the relay would show.
enum DemoCalls {
    /// The guard number the demo calls were made to. Fictional (555-01xx is reserved).
    static let guardNumber = "+16285550199"

    struct Scenario: Identifiable, Sendable, Equatable {
        let id: DemoScenario
        let title: String
        let callerNumber: String
        let durationSeconds: Int
        let verdict: CallVerdict
    }

    /// What "Simulate a scam call" offers, in the relay's order: every scripted call the rules flag. The
    /// neighbour's call (`benign`) is recorded too but not offered — its verdict is `safe`, so there is no alert
    /// to simulate.
    static let scenarios: [Scenario] = [grandparent, irs, techSupport, bankFraud, prize]

    static func scenario(_ id: DemoScenario) -> Scenario? {
        scenarios.first { $0.id == id }
    }

    /// A 'grandchild' in jail after an accident needs bail paid in gift cards and begs for secrecy.
    static let grandparent = Scenario(
        id: .grandparent,
        title: "Grandchild in trouble",
        callerNumber: "+14155550134",
        durationSeconds: 21,
        verdict: CallVerdict(
            sequence: 5,
            category: .scam,
            confidence: 0.984053125,
            level: .high,
            reasons: [
                CallReason(id: "call.gift_cards", title: "Asks for gift cards",
                           detail: "Caller said: “He said the fastest way is with gift cards, Grandma. You go to the pharmacy and buy Apple gift cards, then you read him…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.government_threat", title: "Threatens arrest or government action",
                           detail: "Caller said: “…was in a car accident last night. I'm okay, but they said it was my fault and they arrested me. I'm at the county jail.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.family_emergency", title: "Claims a family member is in trouble",
                           detail: "Caller said: “Grandma? Grandma, it's me. Can you hear me? I'm in so much trouble.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.secrecy", title: "Says not to tell anyone or to stay on the line",
                           detail: "Caller said: “No, and please don't tell Mom or Dad, they'll be so upset. The public defender said I can get out today if the bail is…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.urgency", title: "Creates urgency",
                           detail: "Caller said: “It's how they do it now, it's the court's system. Please hurry, Grandma. And don't hang up, stay on the line with me…”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "This call looks like a scam: Asks for gift cards; Threatens arrest or government action.",
            recommendedAction: "Hang up and call the organisation back on a number you trust.",
            heuristicScore: 0.984053125,
            updatedAt: 0
        )
    )

    /// An 'officer' says the Social Security number is suspended, a warrant is out, and money must move today by wire or gift card.
    static let irs = Scenario(
        id: .irs,
        title: "Social Security suspended",
        callerNumber: "+12025550147",
        durationSeconds: 21,
        verdict: CallVerdict(
            sequence: 4,
            category: .scam,
            confidence: 0.999441859375,
            level: .high,
            reasons: [
                CallReason(id: "call.safe_account", title: "Says to move money to a \"safe account\"",
                           detail: "Caller said: “…the case is open, you will need to move it into a secure government account. Do you have a bank account with more than…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.gift_cards", title: "Asks for gift cards",
                           detail: "Caller said: “…matter. You can pay the verification fee right now by wire transfer or by purchasing Target gift cards. I will stay on…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.government_threat", title: "Threatens arrest or government action",
                           detail: "Caller said: “This is Officer Daniel Reyes with the Social Security Administration. Am I speaking with Margaret Ellis?”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.otp_or_credentials", title: "Asks for a code, PIN, password or Social Security number",
                           detail: "Caller said: “Ma'am, your Social Security number has been suspended due to suspicious activity linked to a drug trafficking case in…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.wire_or_crypto", title: "Asks for a wire transfer or cryptocurrency",
                           detail: "Caller said: “…matter. You can pay the verification fee right now by wire transfer or by purchasing Target gift cards. I will stay…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.secrecy", title: "Says not to tell anyone or to stay on the line",
                           detail: "Caller said: “Do not hang up and do not discuss this case with anyone, it is a federal matter. You can pay the verification fee right…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.payment_pressure", title: "Pressures for a payment, fee or fine",
                           detail: "Caller said: “Ma'am, if you do not cooperate today, the local sheriff will be at your door within the hour. To protect your money…”",
                           severity: .medium, source: .heuristic),
                CallReason(id: "call.urgency", title: "Creates urgency",
                           detail: "Caller said: “…today, the local sheriff will be at your door within the hour. To protect your money while the case is open, you…”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "This call looks like a scam: Says to move money to a \"safe account\"; Asks for gift cards.",
            recommendedAction: "Hang up and call the organisation back on a number you trust.",
            heuristicScore: 0.999441859375,
            updatedAt: 0
        )
    )

    /// 'Microsoft support' finds a virus, takes remote access, 'over-refunds' and demands the difference in gift cards.
    static let techSupport = Scenario(
        id: .techSupport,
        title: "Microsoft support refund",
        callerNumber: "+18005550162",
        durationSeconds: 22,
        verdict: CallVerdict(
            sequence: 4,
            category: .scam,
            confidence: 0.9908875,
            level: .high,
            reasons: [
                CallReason(id: "call.gift_cards", title: "Asks for gift cards",
                           detail: "Caller said: “…of three hundred. I could lose my job. You need to send the extra money back today with gift cards, please, ma'am.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.remote_access", title: "Asks for remote access to a device",
                           detail: "Caller said: “…and the letter R, and type in the address I give you. This will let me connect to your computer and remove the virus.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.secrecy", title: "Says not to tell anyone or to stay on the line",
                           detail: "Caller said: “…allow it. Please don't close this window and don't tell anyone until we fix it. Go to the store now and I'll wait…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.tech_support", title: "Tech-support or refund pretext",
                           detail: "Caller said: “Hello, this is Kevin from Microsoft support. We've detected a virus on your computer that is sending your personal…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.payment_pressure", title: "Pressures for a payment, fee or fine",
                           detail: "Caller said: “…instead of three hundred. I could lose my job. You need to send the extra money back today with gift cards, please,…”",
                           severity: .medium, source: .heuristic),
                CallReason(id: "call.impersonation", title: "Claims to be from a bank, a company or the government",
                           detail: "Caller said: “Hello, this is Kevin from Microsoft support. We've detected a virus on your computer that is sending your personal…”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "This call looks like a scam: Asks for gift cards; Asks for remote access to a device.",
            recommendedAction: "Hang up and call the organisation back on a number you trust.",
            heuristicScore: 0.9908875,
            updatedAt: 0
        )
    )

    /// The 'fraud department' asks for the one-time code and wants the savings moved to a 'safe account' right now.
    static let bankFraud = Scenario(
        id: .bankFraud,
        title: "Bank fraud department",
        callerNumber: "+13125550118",
        durationSeconds: 21,
        verdict: CallVerdict(
            sequence: 6,
            category: .scam,
            confidence: 0.99778515625,
            level: .high,
            reasons: [
                CallReason(id: "call.user_sharing_sensitive", title: "You read out a code or card number",
                           detail: "You said: something that sounds like a card number, a code or a password was read out.",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.safe_account", title: "Says to move money to a \"safe account\"",
                           detail: "Caller said: “…your savings safe, we're going to move it to a temporary safe account under your name while we investigate. I'll…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.otp_or_credentials", title: "Asks for a code, PIN, password or Social Security number",
                           detail: "Caller said: “First I need to verify it's really you. I've just sent a one-time code to your phone. Can you read me the six digits?”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.secrecy", title: "Says not to tell anyone or to stay on the line",
                           detail: "Caller said: “…the criminals could act at any moment. Please stay on the line and don't hang up, and don't call the branch, they…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.callback_refusal", title: "Discourages hanging up or calling back",
                           detail: "Caller said: “…act at any moment. Please stay on the line and don't hang up, and don't call the branch, they can't see this case yet.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.urgency", title: "Creates urgency",
                           detail: "Caller said: “…has access to your account. Don't worry, we can protect your money, but we need to act quickly before they empty it.”",
                           severity: .medium, source: .heuristic),
                CallReason(id: "call.impersonation", title: "Claims to be from a bank, a company or the government",
                           detail: "Caller said: “Good morning, this is Sarah calling from the fraud department at your bank. We've flagged a suspicious charge of nine…”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "This call looks like a scam: You read out a code or card number; Says to move money to a \"safe account\".",
            recommendedAction: "Hang up and call the organisation back on a number you trust.",
            heuristicScore: 0.99778515625,
            updatedAt: 0
        )
    )

    /// A sweepstakes 'win' that needs a processing fee by gift card or wire before five o'clock, and must stay confidential.
    static let prize = Scenario(
        id: .prize,
        title: "Sweepstakes winner",
        callerNumber: "+17025550171",
        durationSeconds: 17,
        verdict: CallVerdict(
            sequence: 3,
            category: .scam,
            confidence: 0.981775,
            level: .high,
            reasons: [
                CallReason(id: "call.gift_cards", title: "Asks for gift cards",
                           detail: "Caller said: “…before five o'clock today or the prize goes to the next winner. You can pay with Walmart gift cards or a wire transfer.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.wire_or_crypto", title: "Asks for a wire transfer or cryptocurrency",
                           detail: "Caller said: “…before five o'clock today or the prize goes to the next winner. You can pay with Walmart gift cards or a wire transfer.”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.secrecy", title: "Says not to tell anyone or to stay on the line",
                           detail: "Caller said: “Ma'am, we ask winners to keep this confidential until the check is delivered, it's for your safety. Please don't tell…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.prize_or_lottery", title: "Announces a prize, lottery or sweepstakes",
                           detail: "Caller said: “Congratulations! This is Michael from the National Sweepstakes Center. Your number was drawn as our grand prize winner o…”",
                           severity: .high, source: .heuristic),
                CallReason(id: "call.urgency", title: "Creates urgency",
                           detail: "Caller said: “…winning, and it has to be paid before five o'clock today or the prize goes to the next winner. You can pay with…”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "This call looks like a scam: Asks for gift cards; Asks for a wire transfer or cryptocurrency.",
            recommendedAction: "Hang up and call the organisation back on a number you trust.",
            heuristicScore: 0.981775,
            updatedAt: 0
        )
    )

    /// A neighbour offers to pick up a ready prescription and asks about the weekend. Nothing suspicious.
    static let benign = Scenario(
        id: .benign,
        title: "Neighbour (benign)",
        callerNumber: "+14155550189",
        durationSeconds: 18,
        verdict: CallVerdict(
            sequence: 2,
            category: .safe,
            confidence: 0.25,
            level: .safe,
            reasons: [
                CallReason(id: "call.urgency", title: "Creates urgency",
                           detail: "Caller said: “Ha, we won't complain. See you Sunday then, and I'll drop the prescription by this afternoon.”",
                           severity: .medium, source: .heuristic),
            ],
            summary: "No signs of a scam so far.",
            recommendedAction: "Nothing suspicious so far.",
            heuristicScore: 0.25,
            updatedAt: 0
        )
    )

    // MARK: - Records

    /// A fresh record for `scenario` that started at `startedAt` and lasted its scripted duration. `alerted` is what
    /// the relay would have done at its default alert floor (`CALLS_ALERT_MIN_LEVEL`, medium).
    static func makeRecord(_ scenario: Scenario, startedAt: Date, isDemo: Bool, isRead: Bool = false) -> FlaggedCallRecord {
        let verdict = scenario.verdict
        return FlaggedCallRecord(
            id: UUID(),
            callerNumber: scenario.callerNumber,
            guardNumber: guardNumber,
            startedAt: startedAt,
            endedAt: startedAt.addingTimeInterval(Double(scenario.durationSeconds)),
            durationSeconds: scenario.durationSeconds,
            statusRaw: CallStatus.completed.rawValue,
            sourceRaw: CallSource.twilio.rawValue,
            categoryRaw: verdict.category.rawValue,
            confidence: verdict.confidence,
            levelRaw: verdict.level.rawValue,
            reasonsJSON: FlaggedCallRecord.encodeReasons(verdict.reasons),
            summary: verdict.summary,
            recommendedAction: verdict.recommendedAction,
            modelIdentifier: verdict.modelIdentifier,
            alerted: verdict.level >= .medium,
            isRead: isRead,
            isDemo: isDemo
        )
    }

    /// Where the seeded calls sit in the week: one earlier today (unread), one two days ago, one five days ago.
    private struct Placement {
        let scenario: Scenario
        let daysAgo: Int
        let minutesAgo: Int
        let hour: Int
        let minute: Int
        let isRead: Bool
    }

    private static let placements: [Placement] = [
        Placement(scenario: grandparent, daysAgo: 0, minutesAgo: 48, hour: 0, minute: 0, isRead: false),
        Placement(scenario: irs, daysAgo: 2, minutesAgo: 0, hour: 10, minute: 15, isRead: true),
        Placement(scenario: techSupport, daysAgo: 5, minutesAgo: 0, hour: 15, minute: 40, isRead: true),
    ]

    /// Inserts the three seeded calls into `context` without saving. Returns them in insertion order.
    @MainActor
    @discardableResult
    static func insertHistory(into context: ModelContext, isDemo: Bool, now: Date = .now, calendar: Calendar = .current) -> [FlaggedCallRecord] {
        placements.map { placement in
            let record = makeRecord(placement.scenario, startedAt: date(for: placement, now: now, calendar: calendar), isDemo: isDemo, isRead: placement.isRead)
            context.insert(record)
            return record
        }
    }

    /// Today's call is "n minutes ago" but never before midnight, so the "Today" section always exists.
    private static func date(for placement: Placement, now: Date, calendar: Calendar) -> Date {
        let startOfToday = calendar.startOfDay(for: now)
        guard placement.daysAgo > 0 else {
            let wanted = now.addingTimeInterval(-Double(placement.minutesAgo) * 60)
            return max(wanted, startOfToday.addingTimeInterval(60))
        }
        let day = calendar.date(byAdding: .day, value: -placement.daysAgo, to: startOfToday) ?? startOfToday
        return day.addingTimeInterval(Double(placement.hour) * 3600 + Double(placement.minute) * 60)
    }
}
