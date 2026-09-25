import XCTest
@testable import PhishCore

final class HeuristicAnalyzerTests: XCTestCase {
    private let analyzer = HeuristicAnalyzer()

    // MARK: - Labeled fixtures (heuristics only)

    func testLabeledFixturesScoreOnTheRightSideOfTheThresholds() {
        for (email, malicious) in SampleEmails.labeled {
            let report = analyzer.analyze(email)
            let summary = "\"\(email.subject)\" from \(email.from?.address ?? "?") scored \(String(format: "%.2f", report.score)); signals: \(report.ids.joined(separator: ", "))"
            if malicious {
                XCTAssertGreaterThanOrEqual(report.score, 0.5, "Malicious fixture should score ≥ 0.5 — \(summary)")
                XCTAssertNotNil(report.maxSeverity, "Malicious fixture should have signals — \(summary)")
            } else {
                let ceiling = SampleEmails.benignScoreTolerances[email.messageID] ?? 0.3
                XCTAssertLessThan(report.score, ceiling, "Benign fixture should score < \(ceiling) — \(summary)")
            }
        }
    }

    func testMaliciousFixturesReachTheHighBandOnAverage() {
        let scores = SampleEmails.malicious.map { analyzer.analyze($0).score }
        let mean = scores.reduce(0, +) / Double(scores.count)
        XCTAssertGreaterThanOrEqual(mean, 0.6, "mean malicious score \(mean)")
        XCTAssertGreaterThanOrEqual(scores.min() ?? 0, 0.6, "every malicious fixture should reach 0.6: \(scores)")
    }

    func testBenignFixturesProduceNoHighSeveritySignals() {
        for email in SampleEmails.benign {
            let report = analyzer.analyze(email)
            let high = report.signals.filter { $0.severity == .high }
            XCTAssertTrue(high.isEmpty, "\(email.subject): unexpected high-severity signals \(high.map(\.id))")
        }
    }

    func testEverySignalHonorsTheContract() {
        for email in SampleEmails.all {
            let report = analyzer.analyze(email)
            for signal in report.signals {
                XCTAssertFalse(signal.title.isEmpty, signal.id)
                XCTAssertFalse(signal.detail.isEmpty, signal.id)
                XCTAssertLessThanOrEqual(signal.detail.count, 300, signal.id)
                XCTAssertTrue(signal.id.contains("."), "family-qualified id expected: \(signal.id)")
                let family = signal.id.split(separator: ".").first.map(String.init) ?? ""
                XCTAssertTrue(["auth", "sender", "link", "content", "attachment", "mitigation"].contains(family), signal.id)
                if family == "mitigation" {
                    XCTAssertEqual(signal.weight, 0, signal.id)
                    XCTAssertEqual(signal.severity, .info, signal.id)
                    for keyword in VerdictEngine.phishingKeywords + VerdictEngine.scamKeywords {
                        XCTAssertFalse(signal.id.contains(keyword), "mitigation id must not carry a category keyword: \(signal.id)")
                    }
                }
            }
            XCTAssertTrue((0...1).contains(report.score))
        }
    }

    func testDerivedCategoriesForFixtures() {
        let engine = VerdictEngine()
        let phish = engine.makeVerdict(report: analyzer.analyze(SampleEmails.paypalPhish), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(phish.category, .phishing)
        XCTAssertEqual(phish.level, .high)
        let scam = engine.makeVerdict(report: analyzer.analyze(SampleEmails.giftCardScam), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(scam.category, .scam)
        let invoice = engine.makeVerdict(report: analyzer.analyze(SampleEmails.fakeInvoiceHTMLAttachment), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(invoice.category, .phishing, "HTML attachment lure is credential phishing")
        let benign = engine.makeVerdict(report: analyzer.analyze(SampleEmails.benignAmazonOrder), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(benign.level, .safe)
        XCTAssertFalse(benign.isFlagged)
    }

    // MARK: - auth.*

    func testAuthFailures() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "PayPal", address: "service@paypal.com"),
            authenticationResults: "mx.google.com; dkim=fail header.i=@paypal.com; spf=softfail smtp.mailfrom=bounce@evil.example; dmarc=fail header.from=paypal.com"
        )
        let report = analyzer.analyze(email)
        XCTAssertTrue(report.has("auth.dkim_fail"))
        XCTAssertTrue(report.has("auth.spf_softfail"))
        XCTAssertTrue(report.has("auth.dmarc_fail"))
        XCTAssertEqual(report.signal("auth.dmarc_fail")?.severity, .high)
        XCTAssertGreaterThan(report.score, 0.6)
    }

    func testSPFFailWeighsMoreThanSoftfail() {
        let hard = analyzer.analyze(TestEmailFactory.email(authenticationResults: "mx; spf=fail smtp.mailfrom=x@acme-example.com"))
        let soft = analyzer.analyze(TestEmailFactory.email(authenticationResults: "mx; spf=softfail smtp.mailfrom=x@acme-example.com"))
        XCTAssertTrue(hard.has("auth.spf_fail"))
        XCTAssertTrue(soft.has("auth.spf_softfail"))
        XCTAssertGreaterThan(hard.score, soft.score)
    }

    func testMissingAuthenticationIsInfoOnlyForUnknownSenders() {
        let report = analyzer.analyze(TestEmailFactory.email())
        XCTAssertTrue(report.has("auth.missing"))
        XCTAssertEqual(report.signal("auth.missing")?.severity, .info)
        XCTAssertEqual(report.score, 0, accuracy: 1e-9)
    }

    func testBrandSenderWithoutDKIMIsFlagged() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "Apple", address: "noreply@apple.com"),
            authenticationResults: "mx.google.com; dkim=none; spf=pass smtp.mailfrom=bounce@apple.com; dmarc=none header.from=apple.com"
        )
        XCTAssertTrue(analyzer.analyze(email).has("auth.brand_unauthenticated"))
    }

    func testDKIMAlignmentAndUnaligned() {
        let aligned = TestEmailFactory.email(
            from: EmailAddress(name: "Amazon.com", address: "order@amazon.com"),
            authenticationResults: "mx; dkim=pass header.d=amazon.com; spf=pass; dmarc=pass header.from=amazon.com"
        )
        let alignedReport = analyzer.analyze(aligned)
        XCTAssertTrue(alignedReport.has("mitigation.brand_authenticated"))
        XCTAssertFalse(alignedReport.has("auth.dkim_unaligned"))

        let unaligned = TestEmailFactory.email(
            from: EmailAddress(name: "Amazon.com", address: "order@amazon.com"),
            authenticationResults: "mx; dkim=pass header.d=bulk-sender.example; spf=pass smtp.mailfrom=x@bulk-sender.example; dmarc=none header.from=amazon.com"
        )
        let unalignedReport = analyzer.analyze(unaligned)
        XCTAssertTrue(unalignedReport.has("auth.dkim_unaligned"))
        XCTAssertEqual(unalignedReport.signal("auth.dkim_unaligned")?.severity, .high)
    }

    func testDMARCPassIsAMitigation() {
        let email = TestEmailFactory.email(authenticationResults: TestEmailFactory.cleanAuth)
        let report = analyzer.analyze(email)
        XCTAssertTrue(report.has("mitigation.dmarc_pass"))
        XCTAssertEqual(report.score, 0)
    }

    // MARK: - sender.*

    func testDisplayNameContainsDifferentAddress() {
        let email = TestEmailFactory.email(from: EmailAddress(name: "ceo@northwindtraders.example", address: "random9921@gmail.com"))
        let report = analyzer.analyze(email)
        XCTAssertTrue(report.has("sender.display_name_address_mismatch"))
        XCTAssertEqual(report.signal("sender.display_name_address_mismatch")?.severity, .high)
    }

    func testDisplayNameBrandFromWrongDomain() {
        let corporate = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "PayPal Service", address: "alerts@secure-notify-mail.com")))
        XCTAssertTrue(corporate.has("sender.brand_display_name_mismatch"))
        let webmail = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Netflix Billing", address: "netflix.billing.team@gmail.com")))
        XCTAssertTrue(webmail.has("sender.free_mail_brand_claim"))
        let legit = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "PayPal", address: "service@mail.paypal.com"), authenticationResults: "mx; dkim=pass header.d=paypal.com; spf=pass; dmarc=pass"))
        XCTAssertFalse(legit.has("sender.brand_display_name_mismatch"))
        XCTAssertFalse(legit.has("sender.free_mail_brand_claim"))
    }

    /// A brand's genuine *alternate* domain, reached through a marketing subdomain, is the brand — not an
    /// impersonation of it. `Tools/PromptLab` found the live case: a DKIM-aligned American Express statement from
    /// `americanexpress@welcome.amex.com` scored 0.54 (a medium alert) on a high-severity display-name
    /// impersonation plus a medium local-part signal, only because `amex.com` was missing from the catalog while
    /// `americanexpress.com` was present. The whole class is pinned here: the short domain, the ESP subdomain in
    /// front of it, and the regional domains that reach the catalog through the `brandKey` regional rule.
    func testGenuineAlternateBrandDomainsAuthenticateInsteadOfImpersonating() {
        func report(name: String, address: String, dkimDomain: String, fromDomain: String) -> HeuristicReport {
            analyzer.analyze(TestEmailFactory.email(
                from: EmailAddress(name: name, address: address),
                subject: "Your September statement is ready",
                textBody: "Your September statement is ready to view. https://www.\(dkimDomain)/account/statements",
                authenticationResults: "mx.google.com; dkim=pass header.d=\(dkimDomain); spf=pass smtp.mailfrom=bounce@\(fromDomain); dmarc=pass header.from=\(dkimDomain)"
            ))
        }

        let amex = report(name: "American Express", address: "americanexpress@welcome.amex.com",
                          dkimDomain: "amex.com", fromDomain: "welcome.amex.com")
        XCTAssertTrue(amex.has("mitigation.brand_authenticated"), amex.ids.joined(separator: ", "))
        XCTAssertFalse(amex.has("sender.brand_display_name_mismatch"))
        XCTAssertFalse(amex.has("sender.localpart_contains_domain"))
        XCTAssertLessThan(amex.score, 0.3, "genuine bank mail must stay well under the benign ceiling")

        // The same shape for every other short or alternate domain the catalog now lists, behind the ESP
        // subdomains real brands send from.
        let alternates: [(brand: String, name: String, local: String, subdomain: String, domain: String)] = [
            ("americanexpress", "American Express", "americanexpress", "welcome", "amex.com"),
            ("bankofamerica", "Bank of America", "bankofamerica", "ealerts", "bofa.com"),
            ("wellsfargo", "Wells Fargo", "wellsfargo", "email", "wf.com"),
            ("citibank", "Citibank", "citibank", "mail", "citi.com"),
            ("chase", "Chase", "alerts", "email", "chase.com"),
            ("usbank", "U.S. Bank", "usbank", "e", "usbank.com"),
            ("discover", "Discover Card", "discover", "email", "discovercard.com"),
            ("navyfederal", "Navy Federal", "navyfederal", "mail", "nfcu.org"),
            ("deutschebank", "Deutsche Bank", "deutschebank", "email", "db.com"),
            ("hsbc", "HSBC", "hsbc", "email", "hsbc.co.uk"),
            ("natwest", "NatWest", "natwest", "email", "natwest.com"),
            // Reached only through the regional rule in `brandKey(forRegistrableDomain:)`.
            ("natwest", "NatWest", "natwest", "email", "natwest.co.uk"),
            ("dhl", "DHL", "dhl", "mail", "dhl.fr"),
        ]
        for case let (brand, name, local, subdomain, domain) in alternates {
            XCTAssertEqual(DomainAnalysis.brandKey(forRegistrableDomain: domain), brand, domain)
            let host = "\(subdomain).\(domain)"
            XCTAssertTrue(DomainAnalysis.isLegitimateDomain(host, for: brand), host)
            let r = report(name: name, address: "\(local)@\(host)", dkimDomain: domain, fromDomain: host)
            XCTAssertTrue(r.has("mitigation.brand_authenticated"), "\(host): \(r.ids.joined(separator: ", "))")
            XCTAssertFalse(r.has("sender.brand_display_name_mismatch"), host)
            XCTAssertFalse(r.has("sender.lookalike_domain"), host)
            XCTAssertLessThan(r.score, 0.3, host)
        }

        // The rule still bites where it should: a domain the brand does not own is an impersonation whatever it
        // abbreviates.
        let fake = report(name: "American Express", address: "americanexpress@amex-statements.com",
                          dkimDomain: "amex-statements.com", fromDomain: "amex-statements.com")
        XCTAssertTrue(fake.has("sender.brand_display_name_mismatch"), fake.ids.joined(separator: ", "))
        XCTAssertFalse(fake.has("mitigation.brand_authenticated"))
    }

    /// The shipped fixture form of the same case, fused the way the app fuses it: even a model that returns 100
    /// cannot lift a genuine, authenticated Amex statement into the alert band.
    func testBenignAmexStatementFixtureIsNeverAlerted() {
        let report = analyzer.analyze(SampleEmails.benignAmexStatement)
        XCTAssertLessThan(report.score, 0.3, report.ids.joined(separator: ", "))
        XCTAssertTrue(report.has("mitigation.brand_authenticated"))
        XCTAssertFalse(report.signals.contains { $0.severity >= .medium && !$0.id.hasPrefix("content.") })

        let hostile = ModelAssessment(isSuspicious: true, category: .phishing, riskScore: 100,
                                      reasons: ["Looks like a bank lure"], summary: "s")
        let verdict = VerdictEngine().makeVerdict(report: report, assessment: hostile, modelIdentifier: "m")
        XCTAssertLessThanOrEqual(verdict.confidence, VerdictEngine.authenticatedBrandConfidenceCap)
        XCTAssertFalse(AlertPolicy().shouldAlert(verdict))
    }

    func testFreeMailCompanyClaim() {
        let report = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Billing Department", address: "billing.dept.2201@outlook.com")))
        XCTAssertTrue(report.has("sender.free_mail_company_claim"))
        let person = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Dana Whitfield", address: "dana@outlook.com")))
        XCTAssertFalse(person.has("sender.free_mail_company_claim"))
    }

    func testLookalikeSenderDomain() {
        let report = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Support", address: "help@paypa1-secure.com")))
        XCTAssertTrue(report.has("sender.lookalike_domain"))
        XCTAssertEqual(report.signal("sender.lookalike_domain")?.severity, .high)
    }

    func testReplyToRules() {
        let toFreemail = analyzer.analyze(TestEmailFactory.email(replyTo: [EmailAddress(name: nil, address: "acme.support.desk@gmail.com")]))
        XCTAssertTrue(toFreemail.has("sender.reply_to_freemail"))

        let lookalike = analyzer.analyze(TestEmailFactory.email(replyTo: [EmailAddress(name: nil, address: "help@paypal-resolution-center.com")]))
        XCTAssertTrue(lookalike.has("sender.reply_to_lookalike"))

        let bothFree = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "M Chen", address: "mchen@gmail.com"), replyTo: [EmailAddress(name: nil, address: "mchen@outlook.com")]))
        XCTAssertTrue(bothFree.has("sender.reply_to_mismatch"))
        XCTAssertEqual(bothFree.signal("sender.reply_to_mismatch")?.severity, .medium)

        // Replies routed to the recipient's own organization are not a mismatch (calendar invites, ticketing).
        let internalReply = analyzer.analyze(TestEmailFactory.email(
            from: EmailAddress(name: "Google Calendar", address: "calendar-notification@google.com"),
            replyTo: [EmailAddress(name: nil, address: "organizer@example.com")]
        ))
        XCTAssertFalse(internalReply.has("sender.reply_to_mismatch"))

        // Same registrable domain (reply.github.com vs github.com) is aligned.
        let subdomain = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "GitHub", address: "notifications@github.com"), replyTo: [EmailAddress(name: nil, address: "reply+x@reply.github.com")]))
        XCTAssertFalse(subdomain.has("sender.reply_to_mismatch"))
    }

    func testSenderHeaderAndReturnPath() {
        let mismatch = analyzer.analyze(TestEmailFactory.email(
            sender: EmailAddress(name: nil, address: "bulk@third-party-relay.example"),
            extraHeaders: [EmailHeader(name: "Return-Path", value: "<bounce@third-party-relay.example>")]
        ))
        XCTAssertTrue(mismatch.has("sender.sender_header_mismatch"))
        XCTAssertTrue(mismatch.has("sender.return_path_mismatch"))

        let list = analyzer.analyze(TestEmailFactory.email(
            sender: EmailAddress(name: nil, address: "list@groups.example"),
            extraHeaders: [EmailHeader(name: "List-Unsubscribe", value: "<mailto:unsub@groups.example>")]
        ))
        XCTAssertFalse(list.has("sender.sender_header_mismatch"))
        XCTAssertTrue(list.has("sender.sender_header_list"))
    }

    func testFromEqualsRecipientWithoutSignature() {
        let me = EmailAddress(name: nil, address: "sam.rivera@example.com")
        let spoof = analyzer.analyze(TestEmailFactory.email(from: me, to: [me], authenticationResults: "mx; spf=fail; dkim=none; dmarc=fail"))
        XCTAssertTrue(spoof.has("sender.from_equals_recipient"))
        let genuine = analyzer.analyze(TestEmailFactory.email(from: me, to: [me], authenticationResults: "mx; spf=pass; dkim=pass header.d=example.com; dmarc=pass"))
        XCTAssertFalse(genuine.has("sender.from_equals_recipient"))
    }

    // MARK: - link.*

    private func html(_ links: [(href: String, text: String)]) -> String {
        "<html><body><p>Hello Sam,</p>" + links.map { "<p><a href=\"\($0.href)\">\($0.text)</a></p>" }.joined() + "</body></html>"
    }

    func testAnchorHostMismatch() {
        let report = analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://evil-login.example/x", "https://www.paypal.com/signin")])))
        XCTAssertTrue(report.has("link.anchor_host_mismatch"))
        XCTAssertEqual(report.signal("link.anchor_host_mismatch")?.severity, .high)
        let sameHost = analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://www.acme-example.com/x", "acme-example.com/x")])))
        XCTAssertFalse(sameHost.has("link.anchor_host_mismatch"))
        let plainText = analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://www.acme-example.com/x", "Click here")])))
        XCTAssertFalse(plainText.has("link.anchor_host_mismatch"))
    }

    func testLookalikeLinkAndBrandMismatch() {
        let lookalike = analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://paypal.com.secure-login.net/a", "Sign in")])))
        XCTAssertTrue(lookalike.has("link.lookalike_domain"))
        XCTAssertTrue(lookalike.has("link.credential_host"), "keyword 'login' in the host name of an unrelated site")
        XCTAssertFalse(lookalike.has("link.credential_path"))
        let path = analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://random-host-2201.example/account/verify?x=1", "Open")])))
        XCTAssertTrue(path.has("link.credential_path"), "path keyword on an unrelated host")

        let brandMismatch = analyzer.analyze(TestEmailFactory.email(
            from: EmailAddress(name: "Netflix", address: "info@netflix.com"),
            subject: "Your Netflix membership",
            htmlBody: html([("https://random-host-2201.example/renew", "Update now")])
        ))
        XCTAssertTrue(brandMismatch.has("link.brand_domain_mismatch"))

        let legit = analyzer.analyze(TestEmailFactory.email(
            from: EmailAddress(name: "Netflix", address: "info@netflix.com"),
            subject: "Your Netflix membership",
            htmlBody: html([("https://www.netflix.com/account", "Manage account")])
        ))
        XCTAssertFalse(legit.has("link.brand_domain_mismatch"))
        XCTAssertFalse(legit.has("link.credential_path"), "credential paths on the brand's own domain are fine")
    }

    func testIPPunycodeShortenerTLDDepthAndSchemes() {
        let report = analyzer.analyze(TestEmailFactory.email(htmlBody: html([
            ("http://192.168.10.5/login.php", "Open"),
            ("https://xn--pypal-4ve.com/", "PayPal"),
            ("https://bit.ly/3abc", "Read more"),
            ("https://secure-update.top/x", "Verify"),
            ("https://a.b.c.d.deep-host.example/x", "Deep"),
            ("http://plain-host.example/page", "Plain"),
            ("javascript:alert(1)", "Run"),
            ("data:text/html;base64,PGh0bWw+", "Open document"),
        ])))
        XCTAssertTrue(report.has("link.ip_literal_host"))
        XCTAssertTrue(report.has("link.punycode_host"))
        XCTAssertTrue(report.has("link.url_shortener"))
        XCTAssertTrue(report.has("link.suspicious_tld"))
        XCTAssertTrue(report.has("link.deep_subdomain"))
        XCTAssertTrue(report.has("link.dangerous_scheme"))
        XCTAssertTrue(report.has("link.plain_http"))
        XCTAssertTrue(report.has("link.credential_path"))
        // Each rule emits exactly once even with several matching links.
        XCTAssertEqual(report.ids.filter { $0 == "link.credential_path" }.count, 1)
    }

    func testFreeHostingAndUserInfoTrick() {
        let report = analyzer.analyze(TestEmailFactory.email(htmlBody: html([
            ("https://docs-portal-2201.web.app/verify", "Open"),
            ("https://www.microsoft.com@evil-host.example/login", "Sign in"),
        ])))
        XCTAssertTrue(report.has("link.free_hosting"))
        XCTAssertEqual(report.signal("link.free_hosting")?.severity, .medium, "credential keyword on free hosting upgrades severity")
        XCTAssertTrue(report.has("link.userinfo_url"))
    }

    func testManyHostsIsLow() {
        let links = (1...12).map { (href: "https://site\($0).example/page", text: "Site \($0)") }
        let report = analyzer.analyze(TestEmailFactory.email(htmlBody: html(links)))
        XCTAssertTrue(report.has("link.many_hosts"))
        XCTAssertEqual(report.signal("link.many_hosts")?.severity, .low)
        XCTAssertLessThan(report.score, 0.3)
    }

    // MARK: - content.*

    func testUrgencyThreatCredentialGreeting() {
        let body = "Dear Customer, unusual activity was detected. Verify your account within 24 hours or it will be suspended."
        let report = analyzer.analyze(TestEmailFactory.email(textBody: body))
        XCTAssertTrue(report.has("content.urgency"))
        XCTAssertTrue(report.has("content.threat"))
        XCTAssertTrue(report.has("content.credential_request"))
        XCTAssertTrue(report.has("content.generic_greeting"))
        XCTAssertTrue(report.signal("content.credential_request")!.detail.localizedCaseInsensitiveContains("verify your account"))
        XCTAssertGreaterThanOrEqual(report.score, 0.6)
    }

    func testPaymentGiftCardWireCrypto() {
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "Please pay a small redelivery fee to receive your parcel.")).has("content.payment_request"))
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "Buy 5 Apple gift cards and send me the codes.")).has("content.gift_card_request"))
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "Send the wire transfer to the new bank details below.")).has("content.wire_transfer_request"))
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "Send 0.2 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh today.")).has("content.crypto_payment_request"))
        // A lone "crypto" mention (news, newsletters) is not enough.
        XCTAssertFalse(analyzer.analyze(TestEmailFactory.email(textBody: "This week in crypto regulation: a summary.")).has("content.crypto_payment_request"))
    }

    func testSecrecyAndExecutiveImpersonation() {
        let body = "Are you available? I'm in back-to-back meetings and can't take calls, so reply here. Keep this between us. Margaret, Chief Executive Officer. Sent from my iPhone"
        let report = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Margaret Chen", address: "m.chen.exec@gmail.com"), to: [EmailAddress(name: nil, address: "sam@northwindtraders.example")], textBody: body))
        XCTAssertTrue(report.has("content.secrecy_request"))
        XCTAssertTrue(report.has("content.executive_impersonation"))
        XCTAssertEqual(report.signal("content.executive_impersonation")?.weight ?? 0, 0.4, accuracy: 1e-9, "free-mail sender to a corporate recipient")
        // Curly apostrophes and odd whitespace do not defeat phrase matching.
        let curly = analyzer.analyze(TestEmailFactory.email(textBody: "I’m in a meeting and can’t take\u{00A0}calls, reply here. Keep this between us."))
        XCTAssertTrue(curly.has("content.executive_impersonation"))
        XCTAssertTrue(curly.has("content.secrecy_request"))
        // A single ordinary cue does not fire ("Reply to this email directly" in GitHub mail).
        XCTAssertFalse(analyzer.analyze(TestEmailFactory.email(textBody: "Reply to this email directly or view it on GitHub.")).has("content.executive_impersonation"))
    }

    func testLureSextortionAndSupportScam() {
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "You have won the lottery! Claim your prize now.")).has("content.advance_fee_payment_lure"))
        let sextortion = analyzer.analyze(TestEmailFactory.email(textBody: "I recorded you through your webcam while you visited adult websites. Pay in bitcoin or I send it to all your contacts."))
        XCTAssertTrue(sextortion.has("content.sextortion_crypto_threat"))
        XCTAssertEqual(sextortion.signal("content.sextortion_crypto_threat")?.severity, .high)
        let support = analyzer.analyze(TestEmailFactory.email(textBody: "Your subscription has been renewed and $399.99 was charged. To cancel or get a refund call our customer care at +1 (888) 555-0134."))
        XCTAssertTrue(support.has("content.support_callback_payment_scam"))
        XCTAssertFalse(analyzer.analyze(TestEmailFactory.email(textBody: "Call me at 555-201-4477 when you land, the invoice for the venue is paid.")).has("content.support_callback_payment_scam"), "phone + invoice without a call-to-cancel is not enough")
    }

    func testSubjectBodyMismatchAndShoutingSubject() {
        let mismatch = analyzer.analyze(TestEmailFactory.email(subject: "Invoice #2291 attached", textBody: "To view the invoice please verify your account and sign in to continue."))
        XCTAssertTrue(mismatch.has("content.subject_body_mismatch_login"))
        let caps = analyzer.analyze(TestEmailFactory.email(subject: "FINAL NOTICE: ACCOUNT SUSPENDED!!!"))
        XCTAssertTrue(caps.has("content.excessive_caps_or_exclamation"))
        XCTAssertFalse(analyzer.analyze(TestEmailFactory.email(subject: "Re: Q4 planning sync")).has("content.excessive_caps_or_exclamation"))
    }

    func testHiddenTextImageOnlyAndHTMLOnlyBodies() {
        let hidden = analyzer.analyze(TestEmailFactory.email(textBody: nil, htmlBody: "<p>Please review your account.</p><div style=\"display:none\">lorem ipsum dolor sit amet consectetur " + String(repeating: "filler ", count: 60) + "</div>"))
        XCTAssertTrue(hidden.has("content.hidden_text"))
        XCTAssertEqual(hidden.signal("content.hidden_text")?.severity, .medium)

        let preheader = analyzer.analyze(TestEmailFactory.email(textBody: nil, htmlBody: "<div style=\"display:none;font-size:1px\">Your weekly digest</div><p>Hi Sam, here is the news.</p>"))
        XCTAssertEqual(preheader.signal("content.hidden_text")?.severity, .low, "short preheaders are common in legitimate mail")

        let imageOnly = analyzer.analyze(TestEmailFactory.email(textBody: nil, htmlBody: "<a href=\"https://promo-host-2201.example/go\"><img src=\"cid:banner\" alt=\"\"></a>"))
        XCTAssertTrue(imageOnly.has("content.image_only_link_body"))

        let htmlOnly = analyzer.analyze(TestEmailFactory.email(textBody: nil, htmlBody: "<p>Your document is ready.</p><p><a href=\"https://docs-host-2201.example/view\">Open document</a></p>"))
        XCTAssertTrue(htmlOnly.has("content.html_only_single_link"))
    }

    // MARK: - attachment.*

    func testDangerousAttachments() {
        let exe = analyzer.analyze(TestEmailFactory.email(attachments: [EmailAttachment(filename: "setup.exe", mimeType: "application/x-msdownload")]))
        XCTAssertTrue(exe.has("attachment.malware_extension"))
        let byMime = analyzer.analyze(TestEmailFactory.email(attachments: [EmailAttachment(filename: "report", mimeType: "application/javascript")]))
        XCTAssertTrue(byMime.has("attachment.malware_extension"))
        let html = analyzer.analyze(TestEmailFactory.email(attachments: [EmailAttachment(filename: "Payment_Advice.HTML", mimeType: "text/html")]))
        XCTAssertTrue(html.has("attachment.html_credential_lure"))
        let macro = analyzer.analyze(TestEmailFactory.email(attachments: [EmailAttachment(filename: "Q3.xlsm")]))
        XCTAssertTrue(macro.has("attachment.macro_document_malware_risk"))
        let archive = analyzer.analyze(TestEmailFactory.email(textBody: "The password for the archive is 1234.", attachments: [EmailAttachment(filename: "docs.zip")]))
        XCTAssertTrue(archive.has("attachment.archive_malware_risk"))
        XCTAssertEqual(archive.signal("attachment.archive_malware_risk")?.severity, .high)
        for (email, _) in [(TestEmailFactory.email(attachments: [EmailAttachment(filename: "invoice.pdf.exe")]), 0),
                           (TestEmailFactory.email(attachments: [EmailAttachment(filename: "photo.jpg                       .js")]), 0)] {
            XCTAssertTrue(analyzer.analyze(email).has("attachment.double_extension_malware"), email.attachments[0].filename)
        }
        let safe = analyzer.analyze(TestEmailFactory.email(attachments: [EmailAttachment(filename: "agenda.pdf", mimeType: "application/pdf"), EmailAttachment(filename: "invite.ics", mimeType: "text/calendar")]))
        XCTAssertFalse(safe.ids.contains { $0.hasPrefix("attachment.") })
    }

    func testInvoiceLureNeedsAnOpenRequest() {
        let lure = analyzer.analyze(TestEmailFactory.email(textBody: "Please see attached invoice and remit payment.", attachments: [EmailAttachment(filename: "Invoice_4471.pdf")]))
        XCTAssertTrue(lure.has("attachment.invoice_lure"))
        let plain = analyzer.analyze(TestEmailFactory.email(textBody: "Here are the notes from today.", attachments: [EmailAttachment(filename: "Invoice_4471.pdf")]))
        XCTAssertFalse(plain.has("attachment.invoice_lure"))
    }

    // MARK: - Aggregation

    func testNoisyOrSaturatesAndMitigationsSubtract() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "PayPal", address: "service@paypal-account-services.com"),
            textBody: "Dear Customer, verify your account within 24 hours or it will be suspended.",
            htmlBody: html([("http://paypal.com.secure-login.net/signin", "https://www.paypal.com/signin")])
        )
        let report = analyzer.analyze(email)
        let weights = report.signals.filter { $0.weight > 0 }.map(\.weight)
        let expected = 1 - weights.reduce(1.0) { $0 * (1 - $1) }
        XCTAssertEqual(report.score, expected, accuracy: 1e-9, "no mitigations here")
        XCTAssertGreaterThan(report.score, 0.9)

        let newsletter = TestEmailFactory.email(
            textBody: "Hi Sam, here are this week's picks. Unsubscribe at any time.",
            authenticationResults: TestEmailFactory.cleanAuth,
            extraHeaders: [EmailHeader(name: "List-Unsubscribe", value: "<https://acme-example.com/u>")]
        )
        let newsletterReport = analyzer.analyze(newsletter)
        XCTAssertTrue(newsletterReport.has("mitigation.newsletter_headers"))
        XCTAssertEqual(newsletterReport.score, 0)
    }

    func testSignalsAreOrderedBySeverityThenWeightWithMitigationsLast() {
        let report = analyzer.analyze(SampleEmails.paypalPhish)
        let risk = report.signals.filter { !$0.id.hasPrefix("mitigation.") }
        for (a, b) in zip(risk, risk.dropFirst()) {
            XCTAssertTrue(a.severity > b.severity || (a.severity == b.severity && a.weight >= b.weight), "\(a.id) before \(b.id)")
        }
        if let firstMitigation = report.signals.firstIndex(where: { $0.id.hasPrefix("mitigation.") }) {
            XCTAssertTrue(report.signals[firstMitigation...].allSatisfy { $0.id.hasPrefix("mitigation.") })
        }
    }

    // MARK: - Hostile input / performance

    func testHostileInputDoesNotBlowUp() {
        let stray = String(repeating: "<a href=\"", count: 20_000) + String(repeating: "<script>", count: 5_000) + String(repeating: "&amp", count: 5_000) + String(repeating: "<!--", count: 2_000)
        let email = TestEmailFactory.email(textBody: nil, htmlBody: stray)
        let start = Date()
        let report = analyzer.analyze(email)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
        XCTAssertLessThanOrEqual(report.links.count, HeuristicReport.maxLinks)
    }

    func testPerformanceOn200KBHTMLBody() {
        var html = "<html><head><style>.x{color:red}</style></head><body>"
        var i = 0
        while html.utf16.count < 200_000 {
            html += "<p>Dear Customer, paragraph \(i) with <b>bold</b> text &amp; entities &copy; and a <a href=\"https://news-host-\(i % 7).example/story/\(i)?utm=1\">story link \(i)</a>. Verify your account within 24 hours.</p>"
            if i % 50 == 0 { html += "<div style=\"display:none\">hidden preheader \(i)</div><script>var x = \(i);</script>" }
            i += 1
        }
        html += "</body></html>"
        let email = TestEmailFactory.email(textBody: nil, htmlBody: html)
        XCTAssertGreaterThanOrEqual(email.htmlBody!.utf16.count, 200_000)

        // Warm up once (automaton build, static tables), then take the best of three runs (the CI box is shared).
        _ = analyzer.analyze(email)
        var best = Double.infinity
        var report = analyzer.analyze(email)
        for _ in 0..<3 {
            let start = Date()
            report = analyzer.analyze(email)
            best = min(best, Date().timeIntervalSince(start))
        }
        // The 50 ms budget applies to optimized code (`swift test -c release -Xswiftc -enable-testing`); an
        // unoptimized debug build is several times slower, so there the bound only guards against super-linear blowups.
        #if DEBUG
        let budget = 0.5
        #else
        let budget = 0.05
        #endif
        XCTAssertLessThan(best, budget, "200 KB HTML analyzed in \(best * 1000) ms")
        XCTAssertEqual(report.links.count, HeuristicReport.maxLinks)
        XCTAssertTrue(report.has("content.credential_request"))
        XCTAssertTrue(report.has("content.hidden_text"))
        XCTAssertFalse(report.bodyText.contains("var x ="), "script content is removed")
    }
}
