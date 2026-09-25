import XCTest
@testable import PhishCore

final class LinkExtractorTests: XCTestCase {
    func testQuotedUnquotedAndSingleQuotedHrefs() {
        let html = """
        <a href="https://a.example/one">One</a>
        <a href='https://a.example/two' class="x">Two</a>
        <a class="btn" HREF=https://a.example/three>Three</a>
        <A href = "https://a.example/four" >Four</A>
        """
        let links = LinkExtractor.links(inHTML: html)
        XCTAssertEqual(links.map(\.href), ["https://a.example/one", "https://a.example/two", "https://a.example/three", "https://a.example/four"])
        XCTAssertEqual(links.map(\.anchorText), ["One", "Two", "Three", "Four"])
    }

    func testEntityEncodedHrefAndNestedTags() {
        let html = "<a href=\"https://a.example/x?a=1&amp;b=2&#38;c=3\"><span><b>Confirm</b> <i>Your</i></span> Account &amp; more</a>"
        let links = LinkExtractor.links(inHTML: html)
        XCTAssertEqual(links.count, 1)
        XCTAssertEqual(links[0].href, "https://a.example/x?a=1&b=2&c=3")
        XCTAssertEqual(links[0].anchorText, "Confirm Your Account & more")
    }

    func testAreaAndImageOnlyAnchors() {
        let html = """
        <map name="m"><area shape="rect" coords="0,0,10,10" href="https://map.example/go" alt="Map target"></map>
        <a href="https://img.example/go"><img src="cid:logo" alt="Company logo"></a>
        <a href="https://noalt.example/go"><img src="cid:x"></a>
        """
        let links = LinkExtractor.links(inHTML: html)
        XCTAssertEqual(links.count, 3)
        XCTAssertEqual(links[0].href, "https://map.example/go")
        XCTAssertEqual(links[0].anchorText, "Map target")
        XCTAssertEqual(links[1].anchorText, "Company logo")
        XCTAssertNil(links[2].anchorText)
    }

    func testMailtoTelFragmentAreFilteredButScriptSchemesKept() {
        let html = """
        <a href="mailto:help@x.example">mail</a><a href="tel:+15550100">call</a><a href="#top">top</a><a href="">empty</a>
        <a href="javascript:alert(1)">js</a><a href="data:text/html;base64,AAAA">data</a><a href="cid:part1">cid</a>
        """
        let links = LinkExtractor.links(inHTML: html)
        XCTAssertEqual(links.map(\.href), ["javascript:alert(1)", "data:text/html;base64,AAAA"])
    }

    func testDedupeIsCaseInsensitiveAndCappedAt50() {
        var html = ""
        for i in 0..<120 { html += "<a href=\"https://a.example/\(i % 60)\">l</a><a href=\"HTTPS://A.EXAMPLE/\(i % 60)\">L</a>" }
        let email = TestEmailFactory.email(textBody: "https://a.example/0 https://b.example/plain", htmlBody: html)
        let links = LinkExtractor.extractLinks(from: email)
        XCTAssertEqual(links.count, HeuristicReport.maxLinks)
        XCTAssertEqual(Set(links.map { $0.href.lowercased() }).count, HeuristicReport.maxLinks)
    }

    func testPlainTextURLs() {
        let text = """
        Visit https://example.com/path?x=1. Or (www.example.org/page). Also see <https://angle.example/x> and http://trail.example/y,
        and https://paren.example/a_(b) plus https://quote.example/q".
        """
        let links = LinkExtractor.links(inText: text)
        XCTAssertEqual(links.map(\.href), [
            "https://example.com/path?x=1",
            "www.example.org/page",
            "https://angle.example/x",
            "http://trail.example/y",
            "https://paren.example/a_(b)",
            "https://quote.example/q",
        ])
        XCTAssertTrue(links.allSatisfy { $0.anchorText == nil })
        XCTAssertEqual(links[1].host, "www.example.org")
    }

    func testHTMLLinksComeBeforeTextLinksAndUnclosedAnchorsAreTolerated() {
        let email = TestEmailFactory.email(
            textBody: "text link https://text.example/z",
            htmlBody: "<a href=\"https://html.example/a\">A<p>unclosed <a href=\"https://html.example/b\">B</a>"
        )
        let links = LinkExtractor.extractLinks(from: email)
        XCTAssertEqual(links.map(\.href), ["https://html.example/a", "https://html.example/b", "https://text.example/z"])
    }

    func testHrefWithNewlinesAndTabsIsNormalized() {
        let html = "<a href=\"https://a.exam\nple/x\ty\">go</a>"
        XCTAssertEqual(LinkExtractor.links(inHTML: html).first?.href, "https://a.example/xy")
    }
}
