import Foundation
import PhishCore

/// Token budgeting shared by the LLM classifiers.
///
/// PhishCore's `PromptBuilder.estimatedTokens(for:)` uses a flat 3.5 characters per token; the app keeps this
/// script-aware variant because it is the more conservative one for the on-device model. The estimate follows Apple's
/// guidance: "three or four characters" per token for Latin-script languages and about one token per character for
/// Chinese, Japanese and Korean, so CJK mail never gets a body that only looks like it fits.
enum PromptFitting {
    /// Characters per token for Latin-script text.
    static let charactersPerToken: Double = 3.5
    /// Tokens left free for the answer, the guided-generation schema and framework overhead.
    static let defaultHeadroomTokens = 700
    /// Body length the prompts start from (matches `PromptBuilder.userPrompt`'s default).
    static let defaultBodyCharacters = 2_500
    /// Never truncate the body below this; the model still needs some text to judge.
    static let minimumBodyCharacters = 200

    /// Rough token count of `text` (see the type comment).
    static func estimatedTokens(for text: String) -> Int {
        var latin = 0
        var dense = 0
        for scalar in text.unicodeScalars {
            if isDenseScript(scalar) { dense += 1 } else { latin += 1 }
        }
        return dense + Int((Double(latin) / charactersPerToken).rounded(.up))
    }

    /// Estimated tokens of the instructions plus the rendered user prompt for a given body limit.
    static func estimatedPromptTokens(
        for input: ClassificationInput,
        maxBodyCharacters: Int,
        instructions: String = PromptBuilder.systemPrompt
    ) -> Int {
        estimatedTokens(for: instructions)
            + estimatedTokens(for: PromptBuilder.userPrompt(for: input, maxBodyCharacters: maxBodyCharacters))
    }

    /// Largest body length (starting at `initial`, shrinking in ~25 % steps) whose estimated prompt leaves
    /// `headroomTokens` free inside `contextSize`. Never returns less than `minimum`.
    static func fittedBodyCharacters(
        for input: ClassificationInput,
        contextSize: Int,
        headroomTokens: Int = defaultHeadroomTokens,
        initial: Int = defaultBodyCharacters,
        minimum: Int = minimumBodyCharacters,
        instructions: String = PromptBuilder.systemPrompt
    ) -> Int {
        let budget = contextSize - headroomTokens
        var candidate = max(initial, minimum)
        while candidate > minimum {
            if estimatedPromptTokens(for: input, maxBodyCharacters: candidate, instructions: instructions) <= budget {
                return candidate
            }
            candidate = max(minimum, candidate - max(candidate / 4, 100))
        }
        return minimum
    }

    /// CJK ideographs, kana, hangul, full-width forms: roughly one token per character.
    private static func isDenseScript(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x1100...0x11FF,   // Hangul Jamo
             0x2E80...0x2FDF,   // CJK radicals
             0x3000...0x30FF,   // CJK symbols, hiragana, katakana
             0x3100...0x31FF,   // bopomofo, hangul compatibility jamo
             0x3400...0x4DBF,   // CJK extension A
             0x4E00...0x9FFF,   // CJK unified ideographs
             0xAC00...0xD7AF,   // Hangul syllables
             0xF900...0xFAFF,   // CJK compatibility ideographs
             0xFF00...0xFFEF,   // full-width forms
             0x20000...0x2FA1F: // CJK extensions B–F
            return true
        default:
            return false
        }
    }
}
