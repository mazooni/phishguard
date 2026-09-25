import Foundation

/// Attachment metadata only. Attachment contents are never fetched.
public struct EmailAttachment: Hashable, Sendable, Codable {
    public var filename: String
    public var mimeType: String?
    public var sizeBytes: Int?

    public init(filename: String, mimeType: String? = nil, sizeBytes: Int? = nil) {
        self.filename = filename
        self.mimeType = mimeType
        self.sizeBytes = sizeBytes
    }

    /// Lowercased path extension, "" when none.
    public var fileExtension: String {
        (filename as NSString).pathExtension.lowercased()
    }
}
