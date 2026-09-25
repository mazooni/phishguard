import Foundation

/// Multi-pattern phrase matcher (Aho-Corasick over a small symbol alphabet).
///
/// All phrase sets are compiled into one automaton, so scanning a text is a single linear pass regardless of how many
/// lexicons the analyzer consults. Matching is case-insensitive, whitespace-insensitive (runs collapse to one space)
/// and word-bounded (a phrase that starts/ends with a letter or digit must not be glued to another letter or digit).
/// A phrase ending in `*` is a word prefix ("prosecut*" matches "prosecuted" and "prosecution"): the end boundary is
/// not enforced and the reported match extends to the end of the word.
struct PhraseAutomaton: Sendable {
    private static let spaceSymbol: Int32 = 37
    private static let firstExtraSymbol: Int32 = 38

    private let alphabetSize: Int
    private let asciiSymbols: [Int32]
    private let extraSymbols: [UInt32: Int32]
    /// `transitions[state * alphabetSize + symbol]` → next state (full DFA, fail links folded in).
    private let transitions: [Int32]
    /// Phrase ids that end in each state (including phrases reachable through fail links).
    private let outputs: [[Int32]]
    /// `outputs[state].isEmpty` without touching the inner array (keeps the hot loop free of ARC traffic).
    private let hasOutput: [Bool]
    private let phraseSet: [Int]
    private let phraseSymbolCount: [Int]
    private let phraseStartsWithWord: [Bool]
    private let phraseEndsWithWord: [Bool]
    /// Prefix phrases ("prosecut*"): the match is extended over the remaining word characters.
    private let phraseIsPrefix: [Bool]
    let setCount: Int

    /// Splits a lexicon entry into its text and whether it is a word prefix (trailing "*").
    private static func phraseSpec(_ phrase: String) -> (text: String, isPrefix: Bool) {
        guard phrase.hasSuffix("*"), phrase.count > 1 else { return (phrase, false) }
        return (String(phrase.dropLast()), true)
    }

    init(sets: [[String]]) {
        setCount = sets.count

        // 1. Alphabet: a–z → 1…26, 0–9 → 27…36, whitespace → 37, other characters used by phrases → 38…
        var ascii = [Int32](repeating: 0, count: 128)
        for v in 0x61...0x7A { ascii[v] = Int32(v - 0x61 + 1) }
        for v in 0x41...0x5A { ascii[v] = Int32(v - 0x41 + 1) }
        for v in 0x30...0x39 { ascii[v] = Int32(v - 0x30 + 27) }
        for v in [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C] { ascii[v] = Self.spaceSymbol }
        var extra: [UInt32: Int32] = [:]
        var nextSymbol = Self.firstExtraSymbol
        for set in sets {
            for phrase in set {
                for scalar in Self.phraseSpec(phrase).text.lowercased().unicodeScalars {
                    if scalar.value < 128 {
                        if ascii[Int(scalar.value)] == 0 { ascii[Int(scalar.value)] = nextSymbol; nextSymbol += 1 }
                    } else if !scalar.properties.isWhitespace, extra[scalar.value] == nil {
                        extra[scalar.value] = nextSymbol; nextSymbol += 1
                    }
                }
            }
        }
        asciiSymbols = ascii
        extraSymbols = extra
        alphabetSize = Int(nextSymbol)

        // 2. Trie.
        var children: [[Int32]] = [[Int32](repeating: -1, count: alphabetSize)]
        var stateOutputs: [[Int32]] = [[]]
        var phraseSet: [Int] = []
        var phraseSymbolCount: [Int] = []
        var startsWithWord: [Bool] = []
        var endsWithWord: [Bool] = []
        var isPrefix: [Bool] = []
        for (setIndex, set) in sets.enumerated() {
            for phrase in set {
                let spec = Self.phraseSpec(phrase)
                let symbols = Self.symbolize(spec.text, ascii: ascii, extra: extra).symbols
                guard !symbols.isEmpty else { continue }
                var state = 0
                for symbol in symbols {
                    let index = Int(symbol)
                    if children[state][index] < 0 {
                        children.append([Int32](repeating: -1, count: alphabetSize))
                        stateOutputs.append([])
                        children[state][index] = Int32(children.count - 1)
                    }
                    state = Int(children[state][index])
                }
                let phraseID = Int32(phraseSet.count)
                stateOutputs[state].append(phraseID)
                phraseSet.append(setIndex)
                phraseSymbolCount.append(symbols.count)
                startsWithWord.append(Self.isWordSymbol(symbols[0]))
                endsWithWord.append(!spec.isPrefix && Self.isWordSymbol(symbols[symbols.count - 1]))
                isPrefix.append(spec.isPrefix)
            }
        }
        self.phraseSet = phraseSet
        self.phraseSymbolCount = phraseSymbolCount
        self.phraseStartsWithWord = startsWithWord
        self.phraseEndsWithWord = endsWithWord
        self.phraseIsPrefix = isPrefix

        // 3. BFS: fail links, merged outputs, full transition table.
        let stateCount = children.count
        var table = [Int32](repeating: 0, count: stateCount * alphabetSize)
        var fail = [Int32](repeating: 0, count: stateCount)
        var queue: [Int32] = []
        for symbol in 0..<alphabetSize {
            let child = children[0][symbol]
            if child >= 0 {
                table[symbol] = child
                fail[Int(child)] = 0
                queue.append(child)
            } else {
                table[symbol] = 0
            }
        }
        var head = 0
        while head < queue.count {
            let state = Int(queue[head]); head += 1
            let failState = Int(fail[state])
            if !stateOutputs[failState].isEmpty { stateOutputs[state].append(contentsOf: stateOutputs[failState]) }
            for symbol in 0..<alphabetSize {
                let child = children[state][symbol]
                if child >= 0 {
                    fail[Int(child)] = table[failState * alphabetSize + symbol]
                    table[state * alphabetSize + symbol] = child
                    queue.append(child)
                } else {
                    table[state * alphabetSize + symbol] = table[failState * alphabetSize + symbol]
                }
            }
        }
        transitions = table
        outputs = stateOutputs
        hasOutput = stateOutputs.map { !$0.isEmpty }
    }

    private static func isWordSymbol(_ symbol: Int32) -> Bool { symbol >= 1 && symbol <= 36 }

    /// Symbol stream with whitespace runs collapsed, plus the scalar offset of each symbol.
    private static func symbolize(_ text: String, ascii: [Int32], extra: [UInt32: Int32]) -> (symbols: [Int32], offsets: [Int]) {
        var symbols: [Int32] = []
        var offsets: [Int] = []
        symbols.reserveCapacity(text.utf8.count)
        offsets.reserveCapacity(text.utf8.count)
        var lastWasSpace = false
        var offset = 0
        for scalar in text.unicodeScalars {
            defer { offset += 1 }
            let symbol: Int32
            if scalar.value < 128 {
                symbol = ascii[Int(scalar.value)]
            } else if scalar.value == 0x2019 || scalar.value == 0x2018 || scalar.value == 0x02BC {
                symbol = ascii[0x27]   // curly apostrophes ("can’t") match the ASCII apostrophe used in phrases
            } else if scalar.value == 0x201C || scalar.value == 0x201D {
                symbol = ascii[0x22]
            } else if scalar.properties.isWhitespace {
                symbol = spaceSymbol
            } else if let mapped = extra[scalar.value] {
                symbol = mapped
            } else if let lower = scalar.properties.lowercaseMapping.unicodeScalars.first, let mapped = extra[lower.value] {
                symbol = mapped
            } else {
                symbol = 0
            }
            if symbol == spaceSymbol {
                if lastWasSpace { continue }
                lastWasSpace = true
            } else {
                lastWasSpace = false
            }
            symbols.append(symbol)
            offsets.append(offset)
        }
        return (symbols, offsets)
    }

    /// Distinct matched phrases per set (as written in `text`, in order of first appearance), at most `limitPerSet`.
    func scan(_ text: String, limitPerSet: Int = 4) -> [[String]] {
        var results = [[String]](repeating: [], count: setCount)
        guard !text.isEmpty, limitPerSet > 0 else { return results }
        let scalars = Array(text.unicodeScalars)
        let (symbols, offsets) = Self.symbolize(text, ascii: asciiSymbols, extra: extraSymbols)
        var seen = [Set<String>](repeating: [], count: setCount)
        var state = 0
        for i in 0..<symbols.count {
            state = Int(transitions[state * alphabetSize + Int(symbols[i])])
            guard hasOutput[state] else { continue }
            for phraseID32 in outputs[state] {
                let phraseID = Int(phraseID32)
                let set = phraseSet[phraseID]
                if results[set].count >= limitPerSet { continue }
                let start = i - phraseSymbolCount[phraseID] + 1
                if phraseStartsWithWord[phraseID], start > 0, Self.isWordSymbol(symbols[start - 1]) { continue }
                if phraseEndsWithWord[phraseID], i + 1 < symbols.count, Self.isWordSymbol(symbols[i + 1]) { continue }
                var end = i
                if phraseIsPrefix[phraseID] {
                    while end + 1 < symbols.count, Self.isWordSymbol(symbols[end + 1]) { end += 1 }
                }
                var view = String.UnicodeScalarView()
                view.append(contentsOf: scalars[offsets[start]...offsets[end]])
                let matched = String(view)
                let key = matched.lowercased()
                if seen[set].insert(key).inserted { results[set].append(matched) }
            }
        }
        return results
    }
}
