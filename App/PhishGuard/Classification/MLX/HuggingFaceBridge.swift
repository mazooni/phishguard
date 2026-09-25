#if !targetEnvironment(simulator)
import Foundation
import HuggingFace
import MLXLMCommon
import Tokenizers

// Hand-written equivalents of the `#hubDownloader(_:)` / `#huggingFaceTokenizerLoader()` macros from
// mlx-swift-lm's MLXHuggingFace product. Writing them out keeps the app free of a macro plugin (no swift-syntax
// build, no "trust plug-in" prompt, no macro-expanded code under warnings-as-errors) and lets the loader be pinned to
// local files so a scan can never start a multi-gigabyte download.

/// `Downloader` over PhishGuard's own `HubClient`, whose `HubCache` lives under Application Support.
struct HubDownloader: MLXLMCommon.Downloader {
    let hub: HubClient
    /// When true the snapshot must already be in the cache; nothing is fetched (used by `MLXClassifier`).
    let localFilesOnly: Bool

    func download(
        id: String,
        revision: String?,
        matching patterns: [String],
        useLatest: Bool,
        progressHandler: @Sendable @escaping (Progress) -> Void
    ) async throws -> URL {
        guard let repo = Repo.ID(rawValue: id) else {
            throw ClassifierError.unavailable("Invalid Hugging Face repository id \"\(id)\".")
        }
        // Progress is not forwarded: the classifier only ever loads models `ModelManager` has fully downloaded, so
        // the cache fast-path returns immediately. (`ModelManager.download` reports its own progress.)
        return try await hub.downloadSnapshot(
            of: repo,
            kind: .model,
            revision: revision ?? "main",
            matching: patterns,
            localFilesOnly: localFilesOnly && !useLatest
        )
    }
}

/// Loads `tokenizer.json` / `tokenizer_config.json` from a snapshot directory with swift-transformers.
struct TransformersTokenizerLoader: MLXLMCommon.TokenizerLoader {
    func load(from directory: URL) async throws -> any MLXLMCommon.Tokenizer {
        let upstream = try await Tokenizers.AutoTokenizer.from(modelFolder: directory)
        return TokenizerAdapter(upstream: upstream)
    }
}

/// Adapts a swift-transformers tokenizer to the protocol MLXLMCommon expects.
struct TokenizerAdapter: MLXLMCommon.Tokenizer {
    let upstream: any Tokenizers.Tokenizer

    func encode(text: String, addSpecialTokens: Bool) -> [Int] {
        upstream.encode(text: text, addSpecialTokens: addSpecialTokens)
    }

    func decode(tokenIds: [Int], skipSpecialTokens: Bool) -> String {
        upstream.decode(tokens: tokenIds, skipSpecialTokens: skipSpecialTokens)
    }

    func convertTokenToId(_ token: String) -> Int? {
        upstream.convertTokenToId(token)
    }

    func convertIdToToken(_ id: Int) -> String? {
        upstream.convertIdToToken(id)
    }

    var bosToken: String? { upstream.bosToken }
    var eosToken: String? { upstream.eosToken }
    var unknownToken: String? { upstream.unknownToken }

    func applyChatTemplate(
        messages: [[String: any Sendable]],
        tools: [[String: any Sendable]]?,
        additionalContext: [String: any Sendable]?
    ) throws -> [Int] {
        do {
            return try upstream.applyChatTemplate(messages: messages, tools: tools, additionalContext: additionalContext)
        } catch Tokenizers.TokenizerError.missingChatTemplate {
            throw MLXLMCommon.TokenizerError.missingChatTemplate
        }
    }
}
#endif
