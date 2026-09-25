import XCTest
@testable import PhishCore

final class HTMLTextExtractorTests: XCTestCase {
    func testStripsScriptStyleHeadCommentsAndTags() {
        let html = """
        <!DOCTYPE html><html><head><title>Ignored title</title><style>p{color:red}</style><script>var x = "<b>not text</b>";</script></head>
        <body><!-- hidden comment --><p>Hello <b>Sam</b>,</p><div>Second<br>line</div><script>alert(1)</script><p>Bye</p></body></html>
        """
        let text = HTMLTextExtractor.text(fromHTML: html)
        XCTAssertEqual(text, "Hello Sam,\nSecond\nline\nBye")
    }

    func testBlockLevelNewlinesAndWhitespaceNormalization() {
        let html = "<table><tr><td>A</td><td>B</td></tr><tr><td>C</td></tr></table><ul><li>one</li><li>two</li></ul><h1>Title</h1>   lots    of \t space\n\n\n<p>end</p>"
        let text = HTMLTextExtractor.text(fromHTML: html)
        XCTAssertEqual(text, "A B\nC\none\ntwo\nTitle\nlots of space\nend")
    }

    func testEntityDecoding() {
        let html = "Tom &amp; Jerry &lt;3 &quot;quotes&quot; &#169; &#xA9; &copy; &euro;100 &hellip; &nbsp;x &rsquo; &NBSP; &#150; &amp &unknown; &#0;"
        let text = HTMLTextExtractor.text(fromHTML: html)
        XCTAssertEqual(text, "Tom & Jerry <3 \"quotes\" © © © €100 … x ’ – & &unknown;", "&NBSP; is decoded case-insensitively, &#150; via Windows-1252, &amp without semicolon")
    }

    func testZeroWidthCharactersAreRemovedSoKeywordsStayIntact() {
        let html = "<p>ver\u{200B}ify your acc\u{00AD}ount</p>"
        XCTAssertEqual(HTMLTextExtractor.text(fromHTML: html), "verify your account")
    }

    func testAttributesContainingGreaterThanAndStrayLessThan() {
        let html = "<p title=\"a > b\">x</p> 3 < 5 and 7 > 2 <img alt='x>y'>"
        XCTAssertEqual(HTMLTextExtractor.text(fromHTML: html), "x\n3 < 5 and 7 > 2")
    }

    func testPlainTextForEmailPrefersTextBody() {
        let email = TestEmailFactory.email(textBody: "  plain   text\n\n\nbody  ", htmlBody: "<p>html</p>")
        XCTAssertEqual(HTMLTextExtractor.plainText(for: email), "plain text\nbody")
        let htmlOnly = TestEmailFactory.email(textBody: "   ", htmlBody: "<p>html</p>")
        XCTAssertEqual(HTMLTextExtractor.plainText(for: htmlOnly), "html")
        XCTAssertEqual(HTMLTextExtractor.plainText(for: TestEmailFactory.email(textBody: nil, htmlBody: nil)), "")
    }

    func testHiddenTextDetection() {
        let html = """
        <div style="display:none;max-height:0">preheader one</div>
        <span style="visibility: hidden">invisible two</span>
        <p style="font-size:1px;color:#ffffff">ref 8813-xk-2211 do not reply</p>
        <p style="FONT-SIZE: 0px">zero size four</p>
        <div style="opacity:0">opaque five</div>
        <td style="color:#fff;background-color:#FFFFFF">same colors six</td>
        <font size="0">font seven</font>
        <div hidden>attr eight</div>
        <div style="mso-hide:all">mso nine</div>
        <div style="position:absolute;left:-9999px">offscreen ten</div>
        <div style="width:0;height:0;overflow:hidden">box eleven</div>
        <p style="color:#fff;background:#0070ba">visible button text</p>
        <p style="opacity:0.9">visible ninety</p>
        <p>visible paragraph</p>
        <div style="display:none">outer <span style="display:none">nested</span> text</div>
        """
        let hidden = HTMLTextExtractor.hiddenText(inHTML: html)
        XCTAssertEqual(hidden, [
            "preheader one", "invisible two", "ref 8813-xk-2211 do not reply", "zero size four", "opaque five",
            "same colors six", "font seven", "attr eight", "mso nine", "offscreen ten", "box eleven", "outer nested text",
        ])
        XCTAssertFalse(hidden.contains { $0.hasPrefix("visible") })
    }

    func testHiddenTextInFixture() {
        let hidden = HTMLTextExtractor.hiddenText(inHTML: SampleEmails.paypalPhish.htmlBody!)
        XCTAssertEqual(hidden, ["ref 8813-xk-2211 do not reply"])
        XCTAssertTrue(HTMLTextExtractor.hiddenText(inHTML: SampleEmails.benignNewsletter.htmlBody!).isEmpty)
    }

    func testHiddenStyleParsing() {
        XCTAssertTrue(HTMLTextExtractor.isHiddenStyle("display : none !important"))
        XCTAssertTrue(HTMLTextExtractor.isHiddenStyle("font-size:0.5px"))
        XCTAssertTrue(HTMLTextExtractor.isHiddenStyle("color: white; background-color: #fff"))
        XCTAssertTrue(HTMLTextExtractor.isHiddenStyle("color: rgb(255, 255, 255)", bgcolorAttribute: "#ffffff"))
        XCTAssertFalse(HTMLTextExtractor.isHiddenStyle("color: #fff"))
        XCTAssertFalse(HTMLTextExtractor.isHiddenStyle("font-size:12px;display:block"))
        XCTAssertFalse(HTMLTextExtractor.isHiddenStyle("opacity:1"))
        XCTAssertFalse(HTMLTextExtractor.isHiddenStyle(""))
    }

    func testInputIsCappedAndLinear() {
        let html = String(repeating: "<div>", count: 300_000) + "<p>tail</p>"
        let start = Date()
        let text = HTMLTextExtractor.text(fromHTML: html)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
        XCTAssertEqual(text, "")   // truncated at 1,000,000 UTF-16 units before "tail"
        let unclosed = String(repeating: "<script>", count: 20_000) + "never closed"
        let start2 = Date()
        _ = HTMLTextExtractor.text(fromHTML: unclosed)
        _ = HTMLTextExtractor.hiddenText(inHTML: String(repeating: "<div style=\"display:none\">x", count: 20_000))
        XCTAssertLessThan(Date().timeIntervalSince(start2), 0.5)
    }
}
