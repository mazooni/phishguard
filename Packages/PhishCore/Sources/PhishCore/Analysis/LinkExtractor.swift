import Foundation

/// Extracts hyperlinks from the HTML and plain-text bodies.
///
/// HTML scanning reuses `HTMLTextExtractor`'s linear tokenizer (quoted/unquoted `href`, `<area>`, nested tags inside
/// anchors, entity-encoded hrefs). `mailto:`, `tel:`, `sms:`, `cid:` and fragment-only links are dropped; `javascript:`
/// and `data:` links are kept because they are signals in their own right.
public enum LinkExtractor {
    /// Maximum number of anchors examined per body (hostile input guard).
    public static let maxAnchorsScanned = 2_000

    /// All links in the message, deduplicated by href (first occurrence wins, case-insensitive), capped at
    /// `HeuristicReport.maxLinks`.
    public static func extractLinks(from email: EmailMessage) -> [EmailLink] {
        var seen = Set<String>()
        var result: [EmailLink] = []
        func add(_ link: EmailLink) {
            guard result.count < HeuristicReport.maxLinks else { return }
            let key = link.href.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !key.isEmpty, !seen.contains(key.lowercased()) else { return }
            seen.insert(key.lowercased())
            result.append(EmailLink(href: key, anchorText: link.anchorText))
        }
        if let html = email.htmlBody {
            links(inHTML: html).forEach(add)
        }
        if let text = email.textBody {
            links(inText: text).forEach(add)
        }
        return result
    }

    /// `<a href>` and `<area href>` occurrences. Anchor text is tag-stripped, entity-decoded and whitespace-collapsed;
    /// for image-only anchors the image's `alt`/`title` is used; for `<area>` the `alt` attribute.
    public static func links(inHTML html: String) -> [EmailLink] {
        let units = HTMLTextExtractor.cappedUnits(of: html)
        var result: [EmailLink] = []
        var i = 0
        var scanned = 0
        while i < units.count, scanned < maxAnchorsScanned, result.count < HeuristicReport.maxLinks * 4 {
            guard let tag = HTMLTextExtractor.nextTag(in: units, from: i) else { break }
            i = tag.end
            guard !tag.isComment, !tag.isClosing else { continue }
            guard tag.name == "a" || tag.name == "area" else { continue }
            scanned += 1
            let attrs = HTMLTextExtractor.attributes(in: units, range: tag.attributeRange)
            guard let rawHref = attrs["href"] else { continue }
            guard let href = normalizedHref(rawHref) else { continue }

            var anchorText: String?
            if tag.name == "a" {
                let end = HTMLTextExtractor.anchorEnd(in: units, from: tag.end)
                let innerUnits = Array(units[tag.end..<end.innerEnd])
                let text = HTMLTextExtractor.text(fromHTML: String(decoding: innerUnits, as: UTF16.self))
                if !text.isEmpty {
                    anchorText = text
                } else {
                    anchorText = imageAlt(in: innerUnits)
                }
                i = end.outerEnd
            } else {
                anchorText = attrs["alt"].map { HTMLTextExtractor.text(fromHTML: $0) }.flatMap { $0.isEmpty ? nil : $0 }
            }
            result.append(EmailLink(href: href, anchorText: anchorText))
        }
        return result
    }

    /// The `alt` (or `title`) of the first `<img>` inside an anchor.
    private static func imageAlt(in units: [UInt16]) -> String? {
        var i = 0
        while let tag = HTMLTextExtractor.nextTag(in: units, from: i) {
            i = tag.end
            guard tag.name == "img" else { continue }
            let attrs = HTMLTextExtractor.attributes(in: units, range: tag.attributeRange)
            if let alt = attrs["alt"] ?? attrs["title"] {
                let text = HTMLTextExtractor.text(fromHTML: alt)
                return text.isEmpty ? nil : text
            }
            return nil
        }
        return nil
    }

    /// Decodes entities, trims, strips surrounding quotes/whitespace and drops non-web schemes.
    /// Returns nil for links that carry no navigational meaning (mailto/tel/sms/cid/fragment/empty).
    static func normalizedHref(_ raw: String) -> String? {
        var href = HTMLTextExtractor.decodeEntities(raw)
        href = href.trimmingCharacters(in: .whitespacesAndNewlines)
        // Remove embedded control characters / whitespace (used to defeat naive scanners).
        href.removeAll { $0.isNewline || $0 == "\t" || $0 == "\r" }
        guard !href.isEmpty, href.utf16.count <= 4_096 else { return nil }
        let lower = href.lowercased()
        if lower.hasPrefix("#") { return nil }
        for scheme in ["mailto:", "tel:", "sms:", "cid:", "callto:", "skype:", "whatsapp:"] where lower.hasPrefix(scheme) {
            return nil
        }
        return href
    }

    /// Bare `http(s)://` and `www.` URLs in plain text.
    public static func links(inText text: String) -> [EmailLink] {
        let capped = String(text.utf16.prefix(HTMLTextExtractor.maxHTMLLength)) ?? text
        let ns = capped as NSString
        var result: [EmailLink] = []
        let range = NSRange(location: 0, length: ns.length)
        plainTextURLRegex.enumerateMatches(in: capped, options: [], range: range) { match, _, stop in
            guard let match else { return }
            var href = ns.substring(with: match.range)
            href = trimTrailingPunctuation(href)
            guard !href.isEmpty else { return }
            result.append(EmailLink(href: href, anchorText: nil))
            if result.count >= HeuristicReport.maxLinks * 2 { stop.pointee = true }
        }
        return result
    }

    private static let plainTextURLRegex: NSRegularExpression = {
        // Linear: a scheme or "www." followed by a run of non-space/non-delimiter characters.
        let pattern = #"(?:https?://|www\.)[^\s<>"'`\[\]{}|\\^]+"#
        // swiftlint:disable:next force_try
        return try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    }()

    private static func trimTrailingPunctuation(_ href: String) -> String {
        var s = href
        while let last = s.last, ".,;:!?'\"".contains(last) { s.removeLast() }
        // Drop an unbalanced trailing ")" — "(see https://example.com/x)".
        while s.hasSuffix(")"), s.filter({ $0 == "(" }).count < s.filter({ $0 == ")" }).count { s.removeLast() }
        return s
    }
}
