import Foundation

/// Hook the coordinator uses to drop cached model state (MLX weights, Foundation Models sessions) at the end of
/// every scan and on memory warnings.
///
/// `ClassifierRegistry` adopts it below. When the registry declares its own `releaseResources()` that method is
/// the witness; until then the no-op default applies, so this compiles either way.
protocol ClassifierResourceReleasing {
    func releaseResources() async
}

extension ClassifierResourceReleasing {
    func releaseResources() async {}
}

extension ClassifierRegistry: ClassifierResourceReleasing {}
