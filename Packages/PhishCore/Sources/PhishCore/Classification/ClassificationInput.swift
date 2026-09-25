import Foundation

/// Everything a classifier gets: the in-memory email plus the heuristic report.
public struct ClassificationInput: Sendable {
    public var email: EmailMessage
    public var report: HeuristicReport

    public init(email: EmailMessage, report: HeuristicReport) {
        self.email = email
        self.report = report
    }
}
