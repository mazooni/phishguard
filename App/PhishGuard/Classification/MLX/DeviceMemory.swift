import Foundation
import os

/// Memory facts used to pick and gate local models.
enum DeviceMemory {
    /// Installed RAM. iPhones report the nominal amount minus what the kernel reserves, so compare with a tolerance.
    static var physicalMemoryBytes: UInt64 { ProcessInfo.processInfo.physicalMemory }

    /// Bytes this process may still allocate before it hits its jetsam limit, or nil when the platform reports
    /// nothing useful (the Simulator returns 0).
    static func availableMemoryBytes() -> Int64? {
        let value = os_proc_available_memory()
        return value > 0 ? Int64(value) : nil
    }

    static func formatted(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .memory)
    }
}
