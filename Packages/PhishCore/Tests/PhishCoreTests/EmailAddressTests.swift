import XCTest
@testable import PhishCore

final class EmailAddressTests: XCTestCase {
    func testParsesNameAndAngleAddressLowercased() {
        let parsed = EmailAddress.parse("John Doe <John@Example.COM>")
        XCTAssertEqual(parsed, [EmailAddress(name: "John Doe", address: "john@example.com")])
        XCTAssertEqual(parsed.first?.domain, "example.com")
    }

    func testParsesQuotedNameContainingComma() {
        let parsed = EmailAddress.parse("\"Doe, John\" <j@d.com>, jane@example.org")
        XCTAssertEqual(parsed.count, 2)
        XCTAssertEqual(parsed[0].name, "Doe, John")
        XCTAssertEqual(parsed[0].address, "j@d.com")
        XCTAssertNil(parsed[1].name)
        XCTAssertEqual(parsed[1].address, "jane@example.org")
    }

    func testParsesEscapedQuotesInName() {
        let parsed = EmailAddress.parse("\"Ann \\\"Sales\\\" Lee\" <ann@corp.example>")
        XCTAssertEqual(parsed.first?.name, "Ann \"Sales\" Lee")
        XCTAssertEqual(parsed.first?.address, "ann@corp.example")
    }

    func testParsesBareAddressesAndCommaLists() {
        let parsed = EmailAddress.parse(" a@b.com ,C@D.org,  <e@f.net> ")
        XCTAssertEqual(parsed.map(\.address), ["a@b.com", "c@d.org", "e@f.net"])
        XCTAssertTrue(parsed.allSatisfy { $0.name == nil })
    }

    func testParsesCommentStyleName() {
        let parsed = EmailAddress.parse("bob@x.com (Bob Smith)")
        XCTAssertEqual(parsed, [EmailAddress(name: "Bob Smith", address: "bob@x.com")])
    }

    func testEmptyAndGarbageInput() {
        XCTAssertEqual(EmailAddress.parse(""), [])
        XCTAssertEqual(EmailAddress.parse("   ,  , "), [])
        XCTAssertEqual(EmailAddress.parse("Undisclosed recipients:;"), [])
    }

    func testDomainWithoutAtIsEmpty() {
        XCTAssertEqual(EmailAddress(name: nil, address: "nodomain").domain, "")
    }

    func testMailtoPrefixIsStripped() {
        XCTAssertEqual(EmailAddress.parse("<mailto:Help@Example.com>").first?.address, "help@example.com")
    }

    func testEmptyNameBecomesNil() {
        XCTAssertNil(EmailAddress(name: "   ", address: "x@y.z").name)
        XCTAssertNil(EmailAddress.parse("\"\" <x@y.z>").first?.name)
    }
}
