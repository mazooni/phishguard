import Foundation
import PhishCore
import SwiftUI

// MARK: - Minimum-level filtering

/// Decides which flagged records the Home list shows, mirroring `AlertPolicy` (level ≥ minimum, never `.safe`).
enum AlertFilter {
    static func includes(level: RiskLevel, minimum: RiskLevel) -> Bool {
        level != .safe && level >= minimum
    }

    static func filter<Item>(_ items: [Item], minimum: RiskLevel, level: (Item) -> RiskLevel) -> [Item] {
        items.filter { includes(level: level($0), minimum: minimum) }
    }
}

// MARK: - Day grouping

/// One list section: all items received on the same calendar day.
struct DaySection<Item>: Identifiable {
    /// Start of the day (in the grouping calendar).
    let day: Date
    let title: String
    var items: [Item]

    var id: Date { day }
}

enum DayGrouping {
    /// Groups `items` by calendar day, newest day first. The relative order of items inside a section is preserved
    /// (pass them newest-first for a newest-first list).
    static func sections<Item>(
        _ items: [Item],
        date: (Item) -> Date,
        now: Date = .now,
        calendar: Calendar = .current
    ) -> [DaySection<Item>] {
        var buckets: [Date: [Item]] = [:]
        for item in items {
            buckets[calendar.startOfDay(for: date(item)), default: []].append(item)
        }
        return buckets.keys.sorted(by: >).map { day in
            DaySection(day: day, title: title(for: day, now: now, calendar: calendar), items: buckets[day] ?? [])
        }
    }

    /// "Today", "Yesterday", "Monday, Sep 15" (same year) or "Sep 15, 2025".
    static func title(for day: Date, now: Date = .now, calendar: Calendar = .current) -> String {
        if calendar.isDate(day, inSameDayAs: now) { return "Today" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(day, inSameDayAs: yesterday) {
            return "Yesterday"
        }
        // Format in the grouping calendar's time zone so a section's start-of-day never shifts to the previous date.
        let style = Date.FormatStyle(locale: calendar.locale ?? .current, calendar: calendar, timeZone: calendar.timeZone)
        if calendar.isDate(day, equalTo: now, toGranularity: .year) {
            return day.formatted(style.weekday(.wide).month(.abbreviated).day())
        }
        return day.formatted(style.month(.abbreviated).day().year())
    }
}

// MARK: - Shield status (Home header)

enum ShieldStatus: Equatable {
    case protected
    case noAccounts
    case notificationsOff

    /// `notificationsAuthorized == nil` means "not known yet" and is treated as authorized so the header does not
    /// flash a warning while the permission is being read.
    static func make(enabledAccountCount: Int, notificationsAuthorized: Bool?) -> ShieldStatus {
        if enabledAccountCount == 0 { return .noAccounts }
        if notificationsAuthorized == false { return .notificationsOff }
        return .protected
    }

    var title: String {
        switch self {
        case .protected: return "Protected"
        case .noAccounts: return "No accounts linked"
        case .notificationsOff: return "Notifications off"
        }
    }

    var detail: String {
        switch self {
        case .protected: return "New mail is checked on this device. You will be alerted only about suspected phishing or scams."
        case .noAccounts: return "Link a Gmail or Outlook account in Settings to start watching your inbox."
        case .notificationsOff: return "Scans still run, but you will not be alerted. Turn on notifications in Settings."
        }
    }

    var symbolName: String {
        switch self {
        case .protected: return "checkmark.shield.fill"
        case .noAccounts: return "person.crop.circle.badge.exclamationmark"
        case .notificationsOff: return "bell.slash.fill"
        }
    }

    var color: Color {
        switch self {
        case .protected: return .green
        case .noAccounts: return .orange
        case .notificationsOff: return .orange
        }
    }
}

// MARK: - Push subscription status (Accounts)

enum PushSubscriptionStatus: Equatable {
    case none
    /// The provider has no webhook at all (IMAP): not a fault, just a different rhythm.
    case unsupported
    case active(until: Date)
    case expiring(at: Date)
    case expired(at: Date)

    static func make(
        expiresAt: Date?,
        now: Date = .now,
        expiringWindow: TimeInterval = 24 * 3600,
        supportsPush: Bool = true
    ) -> PushSubscriptionStatus {
        guard supportsPush else { return .unsupported }
        guard let expiresAt else { return .none }
        if expiresAt <= now { return .expired(at: expiresAt) }
        if expiresAt.timeIntervalSince(now) < expiringWindow { return .expiring(at: expiresAt) }
        return .active(until: expiresAt)
    }

    var label: String {
        switch self {
        case .none: return "No push subscription"
        case .unsupported: return "Checked when you open PhishGuard and in the background"
        case .active(let until): return "Push active until \(until.formatted(date: .abbreviated, time: .shortened))"
        case .expiring(let at): return "Push expiring \(at.formatted(.relative(presentation: .named)))"
        case .expired(let at): return "Push expired \(at.formatted(.relative(presentation: .named)))"
        }
    }

    var symbolName: String {
        switch self {
        case .none: return "bolt.slash"
        case .unsupported: return "clock.arrow.circlepath"
        case .active: return "bolt.fill"
        case .expiring: return "bolt.badge.clock"
        case .expired: return "bolt.trianglebadge.exclamationmark"
        }
    }

    var color: Color {
        switch self {
        case .none, .unsupported: return .secondary
        case .active: return .green
        case .expiring: return .orange
        case .expired: return .red
        }
    }
}

// MARK: - Classifier names

enum ClassifierDisplay {
    /// User-facing name for a `Verdict.modelIdentifier` / `FlaggedEmailRecord.modelIdentifier`.
    ///
    /// An ensemble identifier (`ensemble(a,b)→winner⊘suppressed`, written by `EnsembleClassifier`) names the
    /// model whose risk score decided the verdict, and any second opinion that scored higher but was not
    /// corroborated; without the arrow — the classifier's own identifier, before anything has run — it names the
    /// members instead.
    static func name(forIdentifier identifier: String?) -> String {
        guard let identifier, !identifier.isEmpty else { return "Heuristics only" }
        if identifier == HeuristicsOnlyClassifier.classifierIdentifier { return "Heuristics only" }
        if identifier == AppleFoundationClassifier.classifierIdentifier { return "Apple Intelligence (on-device)" }
        if let ensemble = EnsembleIdentifier.parse(identifier) {
            if let winner = ensemble.winner {
                let base = "Both models (from: \(shortName(forIdentifier: winner))"
                guard !ensemble.suppressed.isEmpty else { return base + ")" }
                let names = ensemble.suppressed.map(shortName(forIdentifier:)).joined(separator: " + ")
                return base + "; \(names) not corroborated)"
            }
            return "Both models (\(ensemble.members.map(shortName(forIdentifier:)).joined(separator: " + ")))"
        }
        if identifier.hasPrefix("mlx:") {
            let repo = String(identifier.dropFirst(4))
            let name = ModelManager.catalog.first { $0.hfRepo == repo }?.displayName ?? repo
            return "Local model (\(name))"
        }
        return identifier
    }

    /// Compact name, for listing several classifiers next to each other ("Apple Intelligence", "Qwen3 4B").
    static func shortName(forIdentifier identifier: String) -> String {
        if identifier == HeuristicsOnlyClassifier.classifierIdentifier { return "Heuristics" }
        if identifier == AppleFoundationClassifier.classifierIdentifier { return "Apple Intelligence" }
        if identifier.hasPrefix("mlx:") {
            let repo = String(identifier.dropFirst(4))
            return ModelManager.catalog.first { $0.hfRepo == repo }?.displayName ?? repo
        }
        if let ensemble = EnsembleIdentifier.parse(identifier) {
            return ensemble.members.map(shortName(forIdentifier:)).joined(separator: " + ")
        }
        return identifier
    }

    /// Footnote for the detail screen.
    static func footnote(forIdentifier identifier: String?) -> String {
        if identifier == nil || identifier == HeuristicsOnlyClassifier.classifierIdentifier {
            return "Analyzed with PhishGuard heuristics only (no language model was available)."
        }
        if let identifier, let ensemble = EnsembleIdentifier.parse(identifier), let winner = ensemble.winner {
            let members = ensemble.members.map(shortName(forIdentifier:)).joined(separator: " and ")
            let base = "Analyzed on this device with \(members) plus PhishGuard heuristics; "
                + "the risk score came from \(shortName(forIdentifier: winner))."
            guard !ensemble.suppressed.isEmpty else { return base }
            let names = ensemble.suppressed.map(shortName(forIdentifier:)).joined(separator: " and ")
            return base + " \(names) rated it higher, but a second model only confirms what other evidence "
                + "already shows, so that score was not used."
        }
        return "Analyzed on this device with \(name(forIdentifier: identifier)) plus PhishGuard heuristics."
    }
}

// MARK: - Byte formatting

enum ByteFormat {
    static func string(_ bytes: Int64) -> String {
        bytes.formatted(.byteCount(style: .file))
    }
}
