import Foundation

/// Which downloadable MLX models are sensible on this device, based on physical memory.
/// Rule of thumb (docs/research/mlx.md): 4-bit models need roughly their download size + 0.3 GB resident;
/// ≥ 8 GB iPhones (16 family and later) handle ~2.3–3 GB models, 6 GB iPhones (15 / 15 Plus) should stay ≤ ~1.2 GB,
/// anything smaller should use Apple Intelligence or heuristics only.
struct DeviceModelRecommendation: Sendable, Equatable {
    enum MemoryClass: Sendable, Equatable {
        case large   // ≥ 8 GB
        case medium  // 6 GB
        case small   // < 6 GB
    }

    static let largeThreshold: UInt64 = 7_000_000_000
    static let mediumThreshold: UInt64 = 5_000_000_000
    static let largeMaxBytes: Int64 = 3_200_000_000
    static let mediumMaxBytes: Int64 = 1_200_000_000

    let physicalMemory: UInt64
    let memoryClass: MemoryClass
    /// Largest download recommended here; nil when local models are not recommended at all.
    let maxRecommendedBytes: Int64?

    init(physicalMemory: UInt64) {
        self.physicalMemory = physicalMemory
        if physicalMemory >= Self.largeThreshold {
            memoryClass = .large
            maxRecommendedBytes = Self.largeMaxBytes
        } else if physicalMemory >= Self.mediumThreshold {
            memoryClass = .medium
            maxRecommendedBytes = Self.mediumMaxBytes
        } else {
            memoryClass = .small
            maxRecommendedBytes = nil
        }
    }

    static var current: DeviceModelRecommendation {
        DeviceModelRecommendation(physicalMemory: ProcessInfo.processInfo.physicalMemory)
    }

    func fits(_ entry: ModelManager.CatalogEntry) -> Bool {
        guard let maxRecommendedBytes else { return false }
        return entry.approxSizeBytes <= maxRecommendedBytes
    }

    /// The first catalog entry (catalog order = preference order) that fits this device.
    func recommendedEntry(in catalog: [ModelManager.CatalogEntry]) -> ModelManager.CatalogEntry? {
        catalog.first(where: fits)
    }

    var memoryDescription: String {
        let gigabytes = Double(physicalMemory) / 1_000_000_000
        let rounded = Int(gigabytes.rounded())
        switch memoryClass {
        case .large: return "This device has about \(rounded) GB of memory, enough for any model in the list."
        case .medium: return "This device has about \(rounded) GB of memory. Models above \(ByteFormat.string(Self.mediumMaxBytes)) may be terminated by iOS while running."
        case .small: return "This device has about \(rounded) GB of memory, which is too little for a downloaded model. Apple Intelligence or heuristics are recommended."
        }
    }

    /// Warning shown when the user selects `entry` although it exceeds the recommendation.
    func warning(for entry: ModelManager.CatalogEntry) -> String? {
        guard !fits(entry) else { return nil }
        if let maxRecommendedBytes {
            return "\(entry.displayName) is larger than the \(ByteFormat.string(maxRecommendedBytes)) recommended for this device. It may run slowly or be terminated by iOS."
        }
        return "\(entry.displayName) is not recommended on this device: it may not have enough memory to run a local model."
    }
}
