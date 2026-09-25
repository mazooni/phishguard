import Foundation

/// A raw header line. Name comparison is case-insensitive via `EmailMessage.header(_:)`.
public struct EmailHeader: Hashable, Sendable {
    public var name: String
    public var value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}
