import Foundation

/// Host/domain helpers used by link and sender heuristics: registrable domains (embedded multi-label public
/// suffixes), IP literals in every browser-accepted form, punycode, free-mail and shortener catalogs, and
/// brand lookalike / typosquat / homoglyph detection backed by a curated list of protected brands.
public enum DomainAnalysis {
    // MARK: - Brand catalog

    /// One impersonated brand: the stable key, the display names it is known by (lowercased, used for mentions in
    /// display names / subjects) and the registrable domains it legitimately sends from or links to.
    public struct Brand: Sendable, Hashable {
        public let key: String
        public let names: [String]
        public let domains: [String]

        public init(key: String, names: [String], domains: [String]) {
            self.key = key
            self.names = names
            self.domains = domains
        }
    }

    /// Curated list (≥ 60) of brands commonly impersonated in phishing: banks, payment, big tech, shipping,
    /// government, crypto exchanges, streaming, retail, telecom, security vendors.
    ///
    /// **Every registrable domain a brand really sends from has to be listed here, including the abbreviated and
    /// alternate ones.** A missing entry is not a missed detection, it is a *false positive on genuine mail*: the
    /// brand's own name in the display name and in the mailbox then reads as impersonation, because nothing
    /// connects "American Express" to the domain the message arrived on. `Tools/PromptLab` reproduced exactly
    /// that — a DKIM-aligned Amex statement from `americanexpress@welcome.amex.com` earned a high-severity
    /// `sender.brand_display_name_mismatch` plus a medium `sender.localpart_contains_domain` and scored 0.54, a
    /// medium alert on a real bank statement, purely because `amex.com` was absent while `americanexpress.com`
    /// and `aexp.com` were present. Hence `amex.com`, `bofa.com`, `wf.com`, `citi.com`, `db.com`, `td.com`,
    /// `discovercard.com`, `nfcu.org` and `fmr.com` below: short domains their owners genuinely use.
    ///
    /// ESP and marketing *subdomains* (`welcome.amex.com`, `email.chase.com`, `e.usbank.com`, `mail.citi.com`,
    /// `ealerts.bankofamerica.com`) need no entries of their own — every lookup here goes through
    /// `registrableDomain`, so a host under a listed domain is already the brand's. Only a separate *registrable*
    /// domain has to be added.
    public static let brands: [Brand] = [
        // Payment / fintech
        Brand(key: "paypal", names: ["paypal"], domains: ["paypal.com", "paypal.me", "paypal-communication.com", "paypal.co.uk", "paypal.de",
                                                          "paypal.fr", "paypal.ca", "paypal.com.au", "paypal.nl"]),
        Brand(key: "venmo", names: ["venmo"], domains: ["venmo.com"]),
        Brand(key: "zelle", names: ["zelle"], domains: ["zellepay.com", "zelle.com"]),
        Brand(key: "cashapp", names: ["cash app", "cashapp"], domains: ["cash.app", "squareup.com", "square.com"]),
        Brand(key: "stripe", names: ["stripe"], domains: ["stripe.com"]),
        Brand(key: "wise", names: ["transferwise"], domains: ["wise.com", "transferwise.com"]),
        Brand(key: "revolut", names: ["revolut"], domains: ["revolut.com"]),
        Brand(key: "klarna", names: ["klarna"], domains: ["klarna.com"]),
        Brand(key: "westernunion", names: ["western union", "westernunion"], domains: ["westernunion.com"]),
        Brand(key: "moneygram", names: ["moneygram"], domains: ["moneygram.com"]),
        Brand(key: "visa", names: ["visa"], domains: ["visa.com"]),
        Brand(key: "mastercard", names: ["mastercard"], domains: ["mastercard.com"]),
        Brand(key: "americanexpress", names: ["american express", "americanexpress", "amex"],
              domains: ["americanexpress.com", "amex.com", "aexp.com"]),
        Brand(key: "discover", names: ["discover card", "discover bank"], domains: ["discover.com", "discovercard.com"]),
        // Banks
        Brand(key: "chase", names: ["chase bank", "jpmorgan chase", "jpmorgan", "chase online", "chase alerts", "chase support", "chase card"], domains: ["chase.com", "jpmorgan.com", "jpmorganchase.com"]),
        Brand(key: "wellsfargo", names: ["wells fargo", "wellsfargo"], domains: ["wellsfargo.com", "wf.com"]),
        Brand(key: "bankofamerica", names: ["bank of america", "bankofamerica", "bofa"], domains: ["bankofamerica.com", "bofa.com"]),
        Brand(key: "citibank", names: ["citibank", "citi bank", "citigroup", "citi"], domains: ["citi.com", "citibank.com", "citigroup.com"]),
        Brand(key: "capitalone", names: ["capital one", "capitalone"], domains: ["capitalone.com"]),
        Brand(key: "usbank", names: ["u.s. bank", "us bank", "usbank"], domains: ["usbank.com"]),
        Brand(key: "pnc", names: ["pnc bank", "pnc"], domains: ["pnc.com"]),
        Brand(key: "truist", names: ["truist"], domains: ["truist.com"]),
        Brand(key: "tdbank", names: ["td bank", "tdbank", "td canada trust"], domains: ["td.com", "tdbank.com"]),
        Brand(key: "hsbc", names: ["hsbc"], domains: ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk"]),
        Brand(key: "barclays", names: ["barclays", "barclaycard"], domains: ["barclays.co.uk", "barclays.com", "barclaycard.co.uk"]),
        Brand(key: "lloyds", names: ["lloyds bank", "lloyds"], domains: ["lloydsbank.com", "lloydsbank.co.uk", "lloydsbanking.com"]),
        Brand(key: "natwest", names: ["natwest"], domains: ["natwest.com"]),
        Brand(key: "santander", names: ["santander"], domains: ["santander.com", "santander.co.uk", "santanderbank.com"]),
        Brand(key: "deutschebank", names: ["deutsche bank", "deutschebank"], domains: ["db.com", "deutsche-bank.de"]),
        Brand(key: "commbank", names: ["commonwealth bank", "commbank"], domains: ["commbank.com.au"]),
        Brand(key: "westpac", names: ["westpac"], domains: ["westpac.com.au"]),
        Brand(key: "scotiabank", names: ["scotiabank"], domains: ["scotiabank.com"]),
        Brand(key: "navyfederal", names: ["navy federal"], domains: ["navyfederal.org", "nfcu.org"]),
        Brand(key: "fidelity", names: ["fidelity investments", "fidelity"], domains: ["fidelity.com", "fmr.com"]),
        Brand(key: "schwab", names: ["charles schwab", "schwab"], domains: ["schwab.com"]),
        Brand(key: "robinhood", names: ["robinhood"], domains: ["robinhood.com"]),
        // Government
        Brand(key: "irs", names: ["internal revenue service", "irs"], domains: ["irs.gov"]),
        Brand(key: "ssa", names: ["social security administration"], domains: ["ssa.gov"]),
        Brand(key: "hmrc", names: ["hm revenue", "hmrc"], domains: ["hmrc.gov.uk", "gov.uk"]),
        Brand(key: "dvla", names: ["dvla"], domains: ["dvla.gov.uk", "gov.uk"]),
        Brand(key: "medicare", names: ["medicare"], domains: ["medicare.gov"]),
        // Shipping
        Brand(key: "usps", names: ["usps", "u.s. postal service", "united states postal service"], domains: ["usps.com"]),
        Brand(key: "ups", names: ["ups"], domains: ["ups.com"]),
        Brand(key: "fedex", names: ["fedex", "federal express"], domains: ["fedex.com"]),
        Brand(key: "dhl", names: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.uk", "dhl-usa.com"]),
        Brand(key: "royalmail", names: ["royal mail", "royalmail"], domains: ["royalmail.com"]),
        Brand(key: "canadapost", names: ["canada post", "canadapost"], domains: ["canadapost.ca", "canadapost-postescanada.ca"]),
        Brand(key: "auspost", names: ["australia post", "auspost"], domains: ["auspost.com.au"]),
        Brand(key: "dpd", names: ["dpd"], domains: ["dpd.com", "dpd.co.uk", "dpd.de"]),
        Brand(key: "evri", names: ["evri"], domains: ["evri.com"]),
        // Big tech
        Brand(key: "apple", names: ["apple", "icloud", "app store", "apple id"], domains: ["apple.com", "icloud.com", "itunes.com", "me.com", "mac.com"]),
        Brand(key: "microsoft", names: ["microsoft", "office 365", "office365", "microsoft 365", "outlook", "onedrive", "sharepoint", "xbox", "azure"],
              domains: ["microsoft.com", "live.com", "outlook.com", "hotmail.com", "office.com", "office365.com", "microsoftonline.com",
                        "windows.com", "xbox.com", "msn.com", "azure.com", "sharepoint.com", "onedrive.com", "skype.com", "microsoftsupport.com",
                        "microsoftrewards.com", "microsoft365.com", "sharepointonline.com"]),
        Brand(key: "google", names: ["google", "gmail", "youtube", "google workspace", "google drive"],
              domains: ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com", "google.co.uk", "withgoogle.com", "goog.le",
                        "google-analytics.com"]),
        Brand(key: "amazon", names: ["amazon", "amazon prime", "prime video", "aws"],
              domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazon.fr", "amazon.it", "amazon.es",
                        "amazon.co.jp", "amazon.in", "amazonaws.com", "amazonses.com", "primevideo.com", "audible.com",
                        "amazon.nl", "amazon.se", "amazon.pl", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.eg", "amazon.com.mx", "amazon.com.br",
                        "amazon.com.tr", "amazon.com.be", "amazon.jobs", "amazon-adsystem.com"]),
        Brand(key: "facebook", names: ["facebook", "meta"], domains: ["facebook.com", "facebookmail.com", "fb.com", "meta.com", "metamail.com"]),
        Brand(key: "instagram", names: ["instagram"], domains: ["instagram.com", "facebookmail.com"]),
        Brand(key: "whatsapp", names: ["whatsapp"], domains: ["whatsapp.com", "whatsapp.net", "facebookmail.com"]),
        Brand(key: "linkedin", names: ["linkedin"], domains: ["linkedin.com", "lnkd.in"]),
        Brand(key: "twitter", names: ["twitter", "x.com"], domains: ["twitter.com", "x.com"]),
        Brand(key: "tiktok", names: ["tiktok"], domains: ["tiktok.com", "tiktokv.com"]),
        Brand(key: "snapchat", names: ["snapchat"], domains: ["snapchat.com", "snap.com"]),
        Brand(key: "dropbox", names: ["dropbox"], domains: ["dropbox.com", "dropboxmail.com"]),
        Brand(key: "docusign", names: ["docusign"], domains: ["docusign.com", "docusign.net"]),
        Brand(key: "adobe", names: ["adobe", "acrobat sign"], domains: ["adobe.com", "adobesign.com", "echosign.com"]),
        Brand(key: "zoom", names: ["zoom"], domains: ["zoom.us", "zoom.com"]),
        Brand(key: "slack", names: ["slack"], domains: ["slack.com", "slack-mail.com"]),
        Brand(key: "github", names: ["github"], domains: ["github.com", "github.io"]),
        Brand(key: "atlassian", names: ["atlassian", "jira", "confluence"], domains: ["atlassian.com", "atlassian.net"]),
        Brand(key: "salesforce", names: ["salesforce"], domains: ["salesforce.com"]),
        Brand(key: "intuit", names: ["intuit", "quickbooks", "turbotax"], domains: ["intuit.com", "quickbooks.com", "turbotax.com"]),
        Brand(key: "yahoo", names: ["yahoo"], domains: ["yahoo.com", "yahoo.co.uk", "yahooinc.com", "aol.com"]),
        // Security vendors / support-scam favourites
        Brand(key: "norton", names: ["norton", "nortonlifelock", "lifelock"], domains: ["norton.com", "nortonlifelock.com", "gendigital.com"]),
        Brand(key: "mcafee", names: ["mcafee"], domains: ["mcafee.com"]),
        Brand(key: "geeksquad", names: ["geek squad", "geeksquad", "best buy", "bestbuy"], domains: ["geeksquad.com", "bestbuy.com"]),
        // Retail / marketplaces
        Brand(key: "walmart", names: ["walmart"], domains: ["walmart.com"]),
        Brand(key: "costco", names: ["costco"], domains: ["costco.com"]),
        Brand(key: "ebay", names: ["ebay"], domains: ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.ca", "ebay.fr", "ebay.it", "ebay.es", "ebay.com.au", "ebay.nl"]),
        Brand(key: "etsy", names: ["etsy"], domains: ["etsy.com"]),
        // myshopify.com hosts every merchant's storefront; it is also listed in `multiTenantBrandDomains`.
        Brand(key: "shopify", names: ["shopify"], domains: ["shopify.com", "shopifyemail.com", "myshopify.com"]),
        Brand(key: "aliexpress", names: ["aliexpress", "alibaba"], domains: ["aliexpress.com", "alibaba.com"]),
        Brand(key: "temu", names: ["temu"], domains: ["temu.com"]),
        Brand(key: "uber", names: ["uber", "uber eats"], domains: ["uber.com"]),
        Brand(key: "airbnb", names: ["airbnb"], domains: ["airbnb.com"]),
        Brand(key: "booking", names: ["booking.com"], domains: ["booking.com"]),
        Brand(key: "doordash", names: ["doordash"], domains: ["doordash.com"]),
        // Crypto
        Brand(key: "coinbase", names: ["coinbase"], domains: ["coinbase.com"]),
        Brand(key: "binance", names: ["binance"], domains: ["binance.com", "binance.us"]),
        Brand(key: "kraken", names: ["kraken"], domains: ["kraken.com"]),
        Brand(key: "cryptocom", names: ["crypto.com"], domains: ["crypto.com"]),
        Brand(key: "metamask", names: ["metamask"], domains: ["metamask.io"]),
        Brand(key: "ledger", names: ["ledger live", "ledger wallet"], domains: ["ledger.com"]),
        Brand(key: "trezor", names: ["trezor"], domains: ["trezor.io"]),
        Brand(key: "blockchain", names: ["blockchain.com"], domains: ["blockchain.com"]),
        Brand(key: "tesla", names: ["tesla"], domains: ["tesla.com"]),
        // Streaming / gaming
        Brand(key: "netflix", names: ["netflix"], domains: ["netflix.com"]),
        Brand(key: "disneyplus", names: ["disney+", "disney plus", "disneyplus"], domains: ["disneyplus.com", "disney.com"]),
        Brand(key: "spotify", names: ["spotify"], domains: ["spotify.com"]),
        Brand(key: "hulu", names: ["hulu"], domains: ["hulu.com"]),
        Brand(key: "hbomax", names: ["hbo max", "hbomax"], domains: ["hbomax.com", "max.com", "hbo.com"]),
        Brand(key: "steam", names: ["steam"], domains: ["steampowered.com", "steamcommunity.com"]),
        Brand(key: "playstation", names: ["playstation"], domains: ["playstation.com", "sony.com"]),
        Brand(key: "nintendo", names: ["nintendo"], domains: ["nintendo.com", "nintendo.net"]),
        Brand(key: "epicgames", names: ["epic games", "epicgames", "fortnite"], domains: ["epicgames.com"]),
        Brand(key: "roblox", names: ["roblox"], domains: ["roblox.com"]),
        Brand(key: "discord", names: ["discord"], domains: ["discord.com", "discordapp.com"]),
        Brand(key: "twitch", names: ["twitch"], domains: ["twitch.tv"]),
        // Telecom / ISPs
        Brand(key: "verizon", names: ["verizon"], domains: ["verizon.com", "verizonwireless.com", "verizon.net"]),
        Brand(key: "att", names: ["at&t"], domains: ["att.com", "att.net"]),
        Brand(key: "tmobile", names: ["t-mobile", "tmobile"], domains: ["t-mobile.com", "tmobile.com"]),
        Brand(key: "xfinity", names: ["xfinity", "comcast"], domains: ["xfinity.com", "comcast.com", "comcast.net"]),
        Brand(key: "vodafone", names: ["vodafone"], domains: ["vodafone.com", "vodafone.co.uk"]),
        Brand(key: "godaddy", names: ["godaddy"], domains: ["godaddy.com", "secureserver.net"]),
    ]

    /// Brands commonly impersonated, mapped to the registrable domains they legitimately send from.
    /// Derived from `brands`; kept as a dictionary for API compatibility.
    public static let protectedBrands: [String: [String]] = Dictionary(uniqueKeysWithValues: brands.map { ($0.key, $0.domains) })

    private static let brandsByKey: [String: Brand] = Dictionary(uniqueKeysWithValues: brands.map { ($0.key, $0) })

    /// Legitimate registrable domains of any protected brand.
    private static let allBrandDomains: Set<String> = Set(brands.flatMap(\.domains))

    /// Listed brand domain → owning brand key (the first brand listing a shared domain such as "facebookmail.com").
    private static let brandKeyByDomain: [String: String] = Dictionary(
        brands.flatMap { brand in brand.domains.map { ($0, brand.key) } },
        uniquingKeysWith: { first, _ in first }
    )

    /// Listed brand domains that are themselves public suffixes ("gov.uk"): nobody outside the registry can register
    /// beneath them, so every host under such an entry belongs to the brand (tax.service.gov.uk, www.gov.uk).
    private static let publicSuffixBrandDomains: [String] = allBrandDomains.filter { multiLabelPublicSuffixes.contains($0) }.sorted()

    /// Brand-owned domains where any customer publishes content under its own subdomain ("evil-tenant.sharepoint.com",
    /// "some-store.myshopify.com", "lh3.googleusercontent.com"). Links there still belong to the brand's infrastructure
    /// (`isLegitimateDomain`), but the brand does not control the page (`isAnyBrandDomain` is false for tenant hosts)
    /// and the tenant's own labels are still checked for lookalikes ("paypal-secure.myshopify.com").
    public static let multiTenantBrandDomains: Set<String> = ["sharepoint.com", "googleusercontent.com", "myshopify.com"]

    /// Brands with no regional presence (domestic agencies and carriers): "<key>.<cc>" is never theirs, so the regional
    /// domain rule in `brandKey(forRegistrableDomain:)` does not apply to them.
    private static let domesticBrands: Set<String> = [
        "irs", "ssa", "hmrc", "dvla", "medicare", "usps", "navyfederal", "royalmail", "canadapost", "auspost", "evri",
    ]

    // MARK: - Catalogs

    /// Multi-label public suffixes (subset of the Public Suffix List) so that `registrableDomain` returns
    /// "example.co.uk" instead of "co.uk".
    public static let multiLabelPublicSuffixes: Set<String> = [
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk", "police.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "gr.jp",
        "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in", "nic.in",
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
        "co.nz", "org.nz", "govt.nz", "net.nz", "ac.nz", "school.nz",
        "com.tr", "gov.tr", "org.tr", "edu.tr", "net.tr",
        "co.za", "org.za", "gov.za", "net.za", "ac.za",
        "com.ar", "gov.ar", "org.ar", "net.ar", "edu.ar",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "org.hk", "gov.hk", "edu.hk", "net.hk",
        "com.tw", "org.tw", "gov.tw", "edu.tw", "net.tw",
        "co.kr", "or.kr", "go.kr", "ne.kr", "ac.kr",
        "com.my", "org.my", "gov.my", "edu.my", "net.my",
        "com.ph", "org.ph", "gov.ph", "edu.ph", "net.ph",
        "com.vn", "org.vn", "gov.vn", "edu.vn", "net.vn",
        "com.pk", "org.pk", "gov.pk", "edu.pk", "net.pk",
        "com.ng", "org.ng", "gov.ng", "edu.ng",
        "com.eg", "org.eg", "gov.eg", "edu.eg",
        "com.sa", "org.sa", "gov.sa", "edu.sa",
        "com.ua", "org.ua", "gov.ua", "edu.ua", "net.ua", "in.ua",
        "com.co", "org.co", "gov.co", "edu.co", "net.co",
        "com.pe", "org.pe", "gob.pe", "edu.pe",
        "com.ve", "org.ve", "gob.ve",
        "com.ec", "org.ec", "gob.ec",
        "com.uy", "org.uy", "gub.uy",
        "com.bo", "org.bo", "gob.bo",
        "com.py", "org.py", "gov.py",
        "com.gt", "com.sv", "com.hn", "com.ni", "com.pa", "com.do", "com.pr", "com.cu",
        "co.il", "org.il", "ac.il", "gov.il", "net.il",
        "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
        "co.id", "or.id", "ac.id", "go.id", "web.id", "my.id",
        "com.bd", "org.bd", "gov.bd",
        "com.np", "org.np", "gov.np",
        "co.th", "ac.th", "go.th", "or.th", "in.th",
        "com.kw", "com.qa", "com.bh", "com.lb", "com.jo", "com.om", "ae.org",
        "co.ke", "or.ke", "go.ke", "ac.ke",
        "co.tz", "co.ug", "co.zw", "co.zm", "co.bw", "co.mz",
        "com.gh", "com.et",
        "com.ru", "org.ru", "net.ru", "msk.ru", "spb.ru",
        "com.es", "org.es", "nom.es", "gob.es",
        "com.pt", "edu.pt", "gov.pt",
        "com.gr", "org.gr", "net.gr", "gov.gr",
        "com.ro", "org.ro",
        "com.hr", "com.mt", "com.cy", "com.ee", "com.lv", "com.lt",
        "co.at", "or.at", "ac.at", "gv.at",
        "com.de", "com.se",
        "co.no", "priv.no",
        "com.fr", "asso.fr", "gouv.fr", "nom.fr", "prd.fr", "tm.fr",
        "co.it", "gov.it", "edu.it",
        "com.be", "ac.be",
        "co.nl", "com.nl",
        "com.ch", "net.ch",
        "co.ie", "gov.ie",
        "co.ca", "gc.ca", "on.ca", "qc.ca", "bc.ca", "ab.ca", "mb.ca", "sk.ca", "ns.ca", "nb.ca", "nl.ca", "pe.ca",
        "com.ge", "com.az", "com.kz", "com.uz", "com.by", "com.mk", "com.al", "com.ba",
    ]

    /// Suffixes of shared hosting platforms where anyone can register a subdomain. Treated like public suffixes
    /// by `registrableDomain` and flagged by the link heuristics.
    public static let freeHostingSuffixes: Set<String> = [
        "blogspot.com", "weebly.com", "wixsite.com", "godaddysites.com", "github.io", "gitlab.io", "herokuapp.com", "web.app",
        "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev", "azurewebsites.net",
        "azurestaticapps.net", "windows.net", "cloudfront.net", "amazonaws.com", "appspot.com", "glitch.me", "repl.co",
        "replit.app", "000webhostapp.com", "duckdns.org", "no-ip.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
        "surge.sh", "canva.site", "carrd.co", "webflow.io", "strikingly.com", "square.site", "wordpress.com", "tumblr.com",
        "weeblysite.com", "yolasite.com", "jimdosite.com", "mystrikingly.com", "hubspotpagebuilder.com", "ipfs.io",
        "dweb.link", "fleek.co", "web.core.windows.net", "blob.core.windows.net",
    ]

    /// Well-known URL shorteners.
    public static let urlShortenerDomains: Set<String> = [
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc",
        "shorturl.at", "rb.gy", "t.ly", "bl.ink", "s.id", "v.gd", "u.to", "x.co", "clck.ru", "qr.ae", "adf.ly", "shorte.st",
        "soo.gd", "1url.com", "tr.im", "snip.ly", "short.io", "tinyurl.co", "shorturl.com", "urlz.fr", "lnk.bio", "t2m.io",
        "cli.re", "gg.gg", "kutt.it", "zzb.bz", "yourls.org", "han.gl", "bitly.ws", "tiny.one",
    ]

    /// TLDs that are disproportionately used for phishing (per multiple abuse reports).
    public static let suspiciousTLDs: Set<String> = [
        "top", "xyz", "icu", "buzz", "club", "click", "link", "work", "gq", "ga", "cf", "ml", "tk", "cyou", "rest", "monster",
        "cam", "zip", "mov", "quest", "sbs", "cfd", "bond", "lol", "pw", "su", "surf", "fun", "site", "online", "website", "space",
        "wang", "win", "bid", "loan", "men", "party", "racing", "review", "science", "stream", "trade", "download", "date", "faith",
        "cricket", "accountant", "beauty", "hair", "skin", "makeup", "boats", "yachts", "autos", "motorcycles", "christmas",
    ]

    /// Consumer webmail / ISP mailbox domains. A "company" mail sent from one of these is a strong scam cue.
    public static let freeMailDomains: Set<String> = [
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.ca", "yahoo.com.au", "yahoo.co.in",
        "ymail.com", "rocketmail.com", "outlook.com", "outlook.co.uk", "outlook.fr", "outlook.de", "hotmail.com", "hotmail.co.uk",
        "hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es", "live.com", "live.co.uk", "live.fr", "msn.com", "aol.com", "icloud.com",
        "me.com", "mac.com", "protonmail.com", "protonmail.ch", "proton.me", "pm.me", "gmx.com", "gmx.de", "gmx.net", "gmx.at", "gmx.ch",
        "web.de", "mail.com", "email.com", "usa.com", "mail.ru", "bk.ru", "list.ru", "inbox.ru", "yandex.com", "yandex.ru", "ya.ru",
        "zoho.com", "zohomail.com", "fastmail.com", "fastmail.fm", "tutanota.com", "tutamail.com", "tuta.io", "hushmail.com",
        "inbox.com", "qq.com", "163.com", "126.com", "sina.com", "naver.com", "daum.net", "hanmail.net", "rediffmail.com",
        "t-online.de", "freenet.de", "laposte.net", "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "libero.it", "virgilio.it",
        "tiscali.it", "seznam.cz", "centrum.cz", "wp.pl", "o2.pl", "onet.pl", "interia.pl", "comcast.net", "att.net", "verizon.net",
        "sbcglobal.net", "bellsouth.net", "cox.net", "charter.net", "earthlink.net", "btinternet.com", "sky.com", "talktalk.net",
        "virginmedia.com", "blueyonder.co.uk", "ntlworld.com", "shaw.ca", "rogers.com", "sympatico.ca", "telus.net", "bigpond.com",
        "optusnet.com.au", "xtra.co.nz", "mail.bg", "abv.bg", "ukr.net", "i.ua", "rambler.ru", "hey.com", "duck.com", "skiff.com",
    ]

    // MARK: - Hosts

    /// Lowercased host for a URL string; nil for non-URL hrefs (e.g. "mailto:", javascript:) or unparsable input.
    /// The host is the one a browser navigates to: backslashes count as path separators in http(s) URLs, so
    /// "https://evil.example\@paypal.com/login" is evil.example (Foundation alone would report paypal.com).
    public static func host(of href: String) -> String? {
        let trimmed = browserNormalizedHref(href.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !trimmed.isEmpty, trimmed.utf16.count <= 4_096 else { return nil }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("mailto:") || lower.hasPrefix("tel:") || lower.hasPrefix("sms:") || lower.hasPrefix("javascript:")
            || lower.hasPrefix("data:") || lower.hasPrefix("cid:") || lower.hasPrefix("#") {
            return nil
        }
        if let components = URLComponents(string: trimmed), let host = components.encodedHost ?? components.host, !host.isEmpty {
            return normalizeHost(host)
        }
        // URLComponents rejects some hostile-but-real URLs (spaces, unusual characters): fall back to a manual scan.
        if let manual = manualHost(of: trimmed) { return manual }
        // Tolerate scheme-less "www.example.com/path".
        if !trimmed.contains("://") {
            if let c = URLComponents(string: "http://" + trimmed), let h = c.encodedHost ?? c.host, h.contains(".") {
                return normalizeHost(h)
            }
            if let manual = manualHost(of: "http://" + trimmed), manual.contains(".") { return manual }
        }
        return nil
    }

    private static func normalizeHost(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    /// Schemes for which WHATWG URL parsing treats "\" exactly like "/" (the browser rule Foundation lacks).
    private static let backslashSchemes: Set<String> = ["http", "https", "ftp", "ws", "wss", "file"]

    /// `href` with every backslash before the query/fragment replaced by "/", for the schemes (and scheme-less
    /// input) that browsers parse that way. Other schemes and percent-encoded "%5C" are left untouched, matching
    /// the browser: "https://evil.example%5C@paypal.com/" really does resolve to paypal.com.
    public static func browserNormalizedHref(_ href: String) -> String {
        guard href.contains("\\") else { return href }
        let scheme = href.prefix { $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." }
        if href[scheme.endIndex...].hasPrefix(":"), !backslashSchemes.contains(scheme.lowercased()) { return href }
        let end = href.firstIndex { $0 == "?" || $0 == "#" } ?? href.endIndex
        return href[..<end].replacingOccurrences(of: "\\", with: "/") + href[end...]
    }

    /// Extracts the authority's host from "scheme://[user@]host[:port]/..." without URL validation.
    private static func manualHost(of url: String) -> String? {
        guard let schemeEnd = url.range(of: "://") else { return nil }
        var authority = url[schemeEnd.upperBound...]
        if let end = authority.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            authority = authority[..<end]
        }
        if let at = authority.lastIndex(of: "@") {
            authority = authority[authority.index(after: at)...]
        }
        var host = String(authority)
        if host.hasPrefix("[") {
            if let close = host.firstIndex(of: "]") { host = String(host[...close]) }
        } else if let colon = host.firstIndex(of: ":") {
            host = String(host[..<colon])
        }
        host = normalizeHost(host.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !host.isEmpty, !host.contains(" ") else { return nil }
        return host
    }

    /// The public suffix of `host` ("co.uk" for "shop.example.co.uk", "com" for "example.com").
    public static func publicSuffix(of host: String) -> String {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return host.lowercased() }
        for length in stride(from: min(4, labels.count - 1), through: 2, by: -1) {
            let candidate = labels.suffix(length).joined(separator: ".")
            if multiLabelPublicSuffixes.contains(candidate) || freeHostingSuffixes.contains(candidate) { return candidate }
        }
        return labels.last ?? ""
    }

    /// Registrable domain: the label directly below the public suffix plus the suffix
    /// ("login.paypal.com" → "paypal.com", "www.example.co.uk" → "example.co.uk", "evil.github.io" → "evil.github.io").
    /// IP literals are returned unchanged.
    public static func registrableDomain(of host: String) -> String {
        let lower = normalizeHost(host)
        if isIPLiteral(lower) { return lower }
        let labels = lower.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return lower }
        let suffixLabelCount = publicSuffix(of: lower).split(separator: ".").count
        let wanted = min(labels.count, suffixLabelCount + 1)
        return labels.suffix(wanted).joined(separator: ".")
    }

    /// The label directly below the public suffix ("paypal" for "www.paypal.com", "example" for "example.co.uk").
    public static func registrableLabel(of host: String) -> String {
        let registrable = registrableDomain(of: host)
        return registrable.split(separator: ".").first.map(String.init) ?? registrable
    }

    /// Number of labels below the registrable domain ("a.b.c.example.com" → 3).
    public static func subdomainDepth(of host: String) -> Int {
        let lower = normalizeHost(host)
        if isIPLiteral(lower) { return 0 }
        let total = lower.split(separator: ".").count
        let registrable = registrableDomain(of: lower).split(separator: ".").count
        return max(0, total - registrable)
    }

    /// True for IPv4 in dotted-decimal, dotted-hex/octal, plain decimal ("3232235777") or hex ("0xc0a80101") forms,
    /// and for IPv6 (bracketed or not, including IPv4-mapped).
    public static func isIPLiteral(_ host: String) -> Bool {
        var h = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        guard !h.isEmpty, h.utf16.count <= 64 else { return false }
        if let zone = h.firstIndex(of: "%") { h = String(h[..<zone]) }   // IPv6 zone id
        if h.contains(":") {
            return isIPv6(h)
        }
        let parts = h.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard (1...4).contains(parts.count) else { return false }
        var values: [UInt64] = []
        for part in parts {
            guard let value = parseIPv4Part(part) else { return false }
            values.append(value)
        }
        // All but the last part must fit a byte; the last part absorbs the remaining bytes.
        for value in values.dropLast() where value > 255 { return false }
        let remainingBytes = 4 - (values.count - 1)
        let maxLast: UInt64 = remainingBytes >= 4 ? 4_294_967_295 : (UInt64(1) << (UInt64(remainingBytes) * 8)) - 1
        return values.last.map { $0 <= maxLast } ?? false
    }

    private static func parseIPv4Part(_ part: String) -> UInt64? {
        guard !part.isEmpty, part.utf16.count <= 12 else { return nil }
        if part.hasPrefix("0x") {
            let digits = part.dropFirst(2)
            guard !digits.isEmpty else { return nil }
            return UInt64(digits, radix: 16)
        }
        if part.count > 1, part.hasPrefix("0"), part.allSatisfy({ $0.isNumber }) {
            return UInt64(part.dropFirst(), radix: 8)
        }
        guard part.allSatisfy({ $0.isNumber }) else { return nil }
        return UInt64(part)
    }

    private static func isIPv6(_ h: String) -> Bool {
        guard h.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "." }) else { return false }
        let doubleColons = h.components(separatedBy: "::").count - 1
        guard doubleColons <= 1 else { return false }
        var groups = h.split(separator: ":", omittingEmptySubsequences: true).map(String.init)
        if let last = groups.last, last.contains(".") {
            guard isIPLiteral(last), !last.contains(":") else { return false }
            groups.removeLast()
            groups.append("0"); groups.append("0")   // an embedded IPv4 counts as two groups
        }
        guard groups.allSatisfy({ !$0.contains(".") && $0.count <= 4 }) else { return false }
        if doubleColons == 1 { return groups.count <= 7 }
        return groups.count == 8
    }

    /// True when any label is IDNA punycode ("xn--").
    public static func isPunycode(_ host: String) -> Bool {
        let lower = host.lowercased()
        if lower.split(separator: ".").contains(where: { $0.hasPrefix("xn--") }) { return true }
        return lower.unicodeScalars.contains { !$0.isASCII }
    }

    /// True when the registrable domain is a consumer webmail / ISP mailbox domain.
    public static func isFreeMailDomain(_ domain: String) -> Bool {
        let lower = normalizeHost(domain)
        return freeMailDomains.contains(lower) || freeMailDomains.contains(registrableDomain(of: lower))
    }

    /// True for known URL shorteners.
    public static func isURLShortener(_ host: String) -> Bool {
        let lower = normalizeHost(host)
        return urlShortenerDomains.contains(lower) || urlShortenerDomains.contains(registrableDomain(of: lower))
    }

    /// True when the host's TLD is in `suspiciousTLDs`.
    public static func hasSuspiciousTLD(_ host: String) -> Bool {
        let lower = normalizeHost(host)
        guard !isIPLiteral(lower), let tld = lower.split(separator: ".").last else { return false }
        return suspiciousTLDs.contains(String(tld))
    }

    /// True when the host lives on a shared/free hosting platform (anyone can create a subdomain).
    public static func isFreeHosting(_ host: String) -> Bool {
        let lower = normalizeHost(host)
        let labels = lower.split(separator: ".").map(String.init)
        guard labels.count >= 3 else { return false }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        let lastThree = labels.suffix(3).joined(separator: ".")
        if freeHostingSuffixes.contains(lastTwo) || freeHostingSuffixes.contains(lastThree) { return true }
        // Google Sites / Forms are frequently abused for credential pages.
        return lower == "sites.google.com" || lower.hasSuffix(".sites.google.com") || lower == "forms.gle"
    }

    /// The brand that owns the registrable domain `registrable`: a listed domain, or — for brands that are neither
    /// ordinary words nor domestic-only — the bare brand key directly under a country-code public suffix
    /// ("paypal.co.uk", "amazon.nl", "ebay.ca", "dhl.fr"). Brands own or defensively register those, while phishing
    /// registrations glue words or digits to the name ("paypal-login.co.uk") or sit on abused TLDs ("paypal.tk"),
    /// which still count as lookalikes. Nil for anything else.
    public static func brandKey(forRegistrableDomain registrable: String) -> String? {
        let lower = normalizeHost(registrable)
        if let key = brandKeyByDomain[lower] { return key }
        return regionalBrandKey(forRegistrableDomain: lower)
    }

    private static func regionalBrandKey(forRegistrableDomain registrable: String) -> String? {
        let suffix = publicSuffix(of: registrable)
        guard registrable.count > suffix.count + 1, registrable.hasSuffix("." + suffix),
              !freeHostingSuffixes.contains(suffix), let tld = suffix.split(separator: ".").last, tld.count == 2,
              !suspiciousTLDs.contains(String(tld)) else { return nil }
        let label = String(registrable.dropLast(suffix.count + 1))
        guard let brand = brandsByKey[label], !dictionaryWordBrands.contains(brand.key), !domesticBrands.contains(brand.key) else {
            return nil
        }
        return brand.key
    }

    /// True when `host` is `entry` or lies beneath it.
    private static func hostBelongs(_ host: String, under entry: String) -> Bool {
        host == entry || host.hasSuffix("." + entry)
    }

    /// True when `host` is a tenant's page on a multi-tenant brand domain ("contoso.sharepoint.com").
    public static func isMultiTenantBrandHost(_ host: String) -> Bool {
        let lower = normalizeHost(host)
        let registrable = registrableDomain(of: lower)
        return multiTenantBrandDomains.contains(registrable) && lower != registrable
    }

    /// True when `host` belongs to the protected brand `key`: its registrable domain is one the brand owns (see
    /// `brandKey(forRegistrableDomain:)`), or the brand lists a public suffix ("gov.uk") that `host` lies beneath.
    /// Tenant pages on the brand's multi-tenant hosting count as the brand's infrastructure here.
    public static func isLegitimateDomain(_ host: String, for brandKey: String) -> Bool {
        guard let brand = brandsByKey[brandKey] else { return false }
        let lower = normalizeHost(host)
        let registrable = registrableDomain(of: lower)
        if brand.domains.contains(registrable) || regionalBrandKey(forRegistrableDomain: registrable) == brandKey { return true }
        return brand.domains.contains { multiLabelPublicSuffixes.contains($0) && hostBelongs(lower, under: $0) }
    }

    /// True when `host` belongs to a protected brand AND the brand controls every page on it. Tenant pages on
    /// multi-tenant brand hosting ("evil-tenant.sharepoint.com", "store.myshopify.com") return false so the
    /// credential-page link rules still apply to them.
    public static func isAnyBrandDomain(_ host: String) -> Bool {
        let lower = normalizeHost(host)
        let registrable = registrableDomain(of: lower)
        if brandKey(forRegistrableDomain: registrable) != nil { return !isMultiTenantBrandHost(lower) }
        return publicSuffixBrandDomains.contains { hostBelongs(lower, under: $0) }
    }

    // MARK: - Lookalikes

    /// Returns the brand key (e.g. "paypal") when the host impersonates a protected brand but is not one of the
    /// brand's legitimate registrable domains. Detects:
    /// - the brand as a label or hyphen-separated token anywhere in the host ("paypal.com.secure-login.net",
    ///   "paypal-resolution-center.com", "secure-paypal.evil.top")
    /// - homoglyph / digit substitutions on any label ("paypa1", "rnicrosoft", "g00gle", "arnazon", Cyrillic letters)
    /// - typosquats: Levenshtein ≤ 1 (brands ≥ 6 chars) or ≤ 2 (brands ≥ 8 chars) on the registrable label
    ///   ("paypall.com", "microsofft.com", "netflixx.com")
    /// - a brand name glued to extra words inside the registrable label for long, distinctive brands ("paypalsecure.com")
    public static func lookalikeBrand(for host: String) -> String? {
        lookalikeMatch(for: host)?.brand.key
    }

    /// Details of a lookalike match.
    public struct LookalikeMatch: Sendable, Hashable {
        public enum Kind: String, Sendable { case brandToken, homoglyph, typosquat, embedded }
        public let brand: Brand
        public let kind: Kind
        /// The host label that triggered the match.
        public let label: String
    }

    public static func lookalikeMatch(for host: String) -> LookalikeMatch? {
        let lower = normalizeHost(host)
        guard !lower.isEmpty, lower.utf16.count <= 253, !isIPLiteral(lower) else { return nil }
        let registrable = registrableDomain(of: lower)
        let labels = lower.split(separator: ".").map(String.init)
        let nonSuffixLabels: [String]
        // On multi-tenant brand hosting only the tenant's labels are examined, and a bare brand name there is the
        // brand's own tenant ("paypal.sharepoint.com"), so every brand needs a companion token / alteration.
        let tenantHost: Bool
        if brandKey(forRegistrableDomain: registrable) != nil {
            // A legitimate brand domain is never a lookalike (of any brand) — except for the tenant part of
            // multi-tenant brand hosting ("paypal-secure.myshopify.com", "paypa1-login.sharepoint.com").
            guard multiTenantBrandDomains.contains(registrable) else { return nil }
            nonSuffixLabels = Array(labels.dropLast(min(registrable.split(separator: ".").count, labels.count)))
            tenantHost = true
        } else {
            let suffixLabelCount = publicSuffix(of: lower).split(separator: ".").count
            nonSuffixLabels = Array(labels.dropLast(min(suffixLabelCount, max(0, labels.count - 1))))
            tenantHost = false
        }
        guard !nonSuffixLabels.isEmpty else { return nil }
        let registrableLabel = nonSuffixLabels.last ?? ""

        // Tokens: labels split on hyphens / underscores.
        var tokens: [String] = []
        for label in nonSuffixLabels {
            for piece in label.split(whereSeparator: { $0 == "-" || $0 == "_" }) where !piece.isEmpty {
                tokens.append(String(piece))
            }
        }

        // 1. Exact brand token / label, optionally with digits glued on ("paypal1", "2amazon"). Brands that are also
        //    ordinary words ("wise", "chase", "apple") need a phishing-style companion token ("apple-id-verify.com").
        let hasCompanion = tokens.contains { companionTokens.contains($0) || (!$0.isEmpty && $0.allSatisfy(\.isNumber)) }
        for brand in brands {
            let needsCompanion = tenantHost || dictionaryWordBrands.contains(brand.key)
            if tokens.contains(brand.key), !needsCompanion || hasCompanion {
                return LookalikeMatch(brand: brand, kind: .brandToken, label: brand.key)
            }
            guard brand.key.count >= 4, !needsCompanion else { continue }
            for token in tokens where token.count > brand.key.count {
                if token.trimmingCharacters(in: .decimalDigits) == brand.key {
                    return LookalikeMatch(brand: brand, kind: .brandToken, label: token)
                }
            }
        }

        // 2. Homoglyph / digit substitution on any token ("paypa1", "rnicrosoft", "g00gle").
        for token in tokens where token.count >= 4 {
            let normalized = homoglyphNormalized(token)
            guard normalized != token else { continue }
            for brand in brands where normalized == brand.key {
                return LookalikeMatch(brand: brand, kind: .homoglyph, label: token)
            }
        }

        // 3. Typosquat by edit distance on the registrable label and its hyphen tokens.
        let candidates = Set([registrableLabel] + registrableLabel.split(separator: "-").map(String.init))
        for candidate in candidates where candidate.count >= 5 {
            for brand in brands where brand.key.count >= 6 && !dictionaryWordBrands.contains(brand.key) && candidate != brand.key {
                let limit = brand.key.count >= 8 ? 2 : 1
                guard abs(brand.key.count - candidate.count) <= limit else { continue }
                if levenshtein(candidate, brand.key, limit: limit) <= limit {
                    return LookalikeMatch(brand: brand, kind: .typosquat, label: candidate)
                }
            }
        }

        // 4. Brand name glued to typical phishing words inside one label ("paypalsecure", "mypaypal", "amazon2024").
        for label in nonSuffixLabels where label.count >= 7 {
            let squashed = homoglyphNormalized(label.replacingOccurrences(of: "-", with: ""))
            for brand in brands where embeddedMatchBrands.contains(brand.key) && squashed.count > brand.key.count {
                guard let range = squashed.range(of: brand.key) else { continue }
                let before = String(squashed[..<range.lowerBound])
                let after = String(squashed[range.upperBound...])
                if isCompanionRemainder(before), isCompanionRemainder(after) {
                    return LookalikeMatch(brand: brand, kind: .embedded, label: label)
                }
            }
        }
        return nil
    }

    /// True when the brand key is an ordinary word or a common name ("apple", "chase", "zoom", "visa"), so a bare
    /// mention of it is weak evidence on its own. Rules that require a *whole* DNS label or address token to equal the
    /// brand (`brandSubdomainMatch`) do not need this gate; rules that search inside longer text do.
    public static func isDictionaryWordBrand(_ key: String) -> Bool { dictionaryWordBrands.contains(key) }

    /// Brand keys that are ordinary words or names and therefore need extra evidence before a host counts as a lookalike.
    private static let dictionaryWordBrands: Set<String> = [
        "wise", "chase", "discover", "booking", "steam", "apple", "visa", "ledger", "uber", "zoom", "slack", "hulu", "temu",
        "kraken", "twitch", "discord", "stripe", "medicare", "evri", "target", "square", "affirm", "truist",
    ]

    /// Words that phishing hosts glue to a brand name ("paypal-login", "apple-id-verify", "mypaypal", "amazon-support").
    private static let companionTokens: Set<String> = [
        "login", "log", "logon", "signin", "sign", "secure", "security", "verify", "verification", "account", "accounts", "update",
        "updates", "support", "help", "helpdesk", "service", "services", "billing", "bill", "alert", "alerts", "notice",
        "notification", "notifications", "notify", "pay", "payment", "payments", "wallet", "id", "auth", "confirm", "team",
        "official", "refund", "refunds", "my", "mail", "online", "portal", "center", "centre", "info", "access", "web", "app",
        "apps", "cloud", "store", "shop", "delivery", "deliveries", "tracking", "track", "package", "parcel", "shipping",
        "invoice", "docs", "document", "documents", "file", "files", "share", "drive", "com", "net", "org", "co", "www",
        "customer", "care", "reset", "recovery", "recover", "unlock", "limited", "suspended", "claim", "claims", "reward",
        "rewards", "bonus", "gift", "card", "cards", "benefits", "renewal", "renew", "subscription", "membership", "member",
        "e", "i", "us", "uk", "ca", "eu", "de", "fr", "au", "go2", "safe", "safety",
        "protect", "protection", "check", "status", "order", "orders", "prime", "event", "events", "giveaway", "promo",
        "crypto", "exchange", "trade", "trading", "bank", "banking", "money", "cash", "credit", "loan", "tax", "gov",
        "admin", "server", "sso", "auth2", "oauth", "session", "user", "users", "email", "inbox", "webmail", "office",
        "365", "2fa", "mfa", "hr", "it", "desk", "wallets", "key", "keys", "restore", "review", "case", "dispute", "fraud",
    ]

    /// True when `remainder` (the label text around an embedded brand) is empty, digits, or a chain of companion words.
    private static func isCompanionRemainder(_ remainder: String) -> Bool {
        if remainder.isEmpty { return true }
        if remainder.allSatisfy(\.isNumber) { return true }
        var memo: [Int: Bool] = [:]
        let chars = Array(remainder)
        func segmentable(_ start: Int) -> Bool {
            if start == chars.count { return true }
            if let cached = memo[start] { return cached }
            var result = false
            var end = start + 1
            while end <= chars.count, end - start <= 14 {
                let piece = String(chars[start..<end])
                if companionTokens.contains(piece) || piece.allSatisfy(\.isNumber) {
                    if segmentable(end) { result = true; break }
                }
                end += 1
            }
            memo[start] = result
            return result
        }
        return segmentable(0)
    }

    /// Brands whose names are distinctive enough that finding them inside a longer label is meaningful
    /// (excluded: dictionary words such as "discover", "chase", "steam", "apple", "ledger", "booking").
    private static let embeddedMatchBrands: Set<String> = [
        "paypal", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin", "docusign",
        "dropbox", "coinbase", "binance", "metamask", "wellsfargo", "bankofamerica", "citibank", "capitalone", "santander",
        "barclays", "natwest", "americanexpress", "mastercard", "westernunion", "moneygram", "spotify", "playstation",
        "nintendo", "verizon", "tmobile", "xfinity", "vodafone", "godaddy", "salesforce", "atlassian", "robinhood", "fidelity",
        "walmart", "costco", "shopify", "aliexpress", "doordash", "airbnb", "twitter", "tiktok", "snapchat", "geeksquad",
        "mcafee", "norton", "epicgames", "roblox", "discord", "twitch", "revolut", "klarna", "scotiabank", "commbank",
        "westpac", "royalmail", "canadapost", "auspost", "fedex", "zelle", "venmo", "cashapp",
    ]

    /// Maps common visual substitutions back to ASCII letters: digits ("0"→"o", "1"→"l", "3"→"e", "4"→"a", "5"→"s",
    /// "7"→"t", "8"→"b", "9"→"g"), letter pairs ("rn"→"m", "vv"→"w", "cl"→"d") and Cyrillic / Greek confusables.
    public static func homoglyphNormalized(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        let scalars = Array(text.lowercased().unicodeScalars)
        var i = 0
        while i < scalars.count {
            let s = scalars[i]
            let next: UnicodeScalar? = i + 1 < scalars.count ? scalars[i + 1] : nil
            if s == "r", next == "n" { out.append("m"); i += 2; continue }
            if s == "v", next == "v" { out.append("w"); i += 2; continue }
            if s == "c", next == "l" { out.append("d"); i += 2; continue }
            if let mapped = homoglyphMap[s] { out.unicodeScalars.append(mapped) } else { out.unicodeScalars.append(s) }
            i += 1
        }
        return out
    }

    private static let homoglyphMap: [UnicodeScalar: UnicodeScalar] = [
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l", "!": "i", "$": "s", "@": "a",
        // Cyrillic
        "\u{0430}": "a", "\u{0435}": "e", "\u{043E}": "o", "\u{0440}": "p", "\u{0441}": "c", "\u{0445}": "x", "\u{0443}": "y",
        "\u{0456}": "i", "\u{0458}": "j", "\u{04BB}": "h", "\u{0455}": "s", "\u{0501}": "d", "\u{051B}": "q", "\u{0461}": "w",
        "\u{043A}": "k", "\u{043C}": "m", "\u{0442}": "t", "\u{0432}": "b", "\u{043D}": "h",
        // Greek
        "\u{03B1}": "a", "\u{03BF}": "o", "\u{03C1}": "p", "\u{03B5}": "e", "\u{03B9}": "i", "\u{03BA}": "k", "\u{03BD}": "v",
        "\u{03C4}": "t", "\u{03C5}": "u", "\u{03C7}": "x", "\u{03B3}": "y",
        // Latin extended / accents commonly used in IDN homographs
        "\u{00E0}": "a", "\u{00E1}": "a", "\u{00E2}": "a", "\u{00E3}": "a", "\u{00E4}": "a", "\u{00E5}": "a", "\u{0101}": "a",
        "\u{00E8}": "e", "\u{00E9}": "e", "\u{00EA}": "e", "\u{00EB}": "e", "\u{0113}": "e", "\u{0117}": "e",
        "\u{00EC}": "i", "\u{00ED}": "i", "\u{00EE}": "i", "\u{00EF}": "i", "\u{0131}": "i", "\u{012B}": "i",
        "\u{00F2}": "o", "\u{00F3}": "o", "\u{00F4}": "o", "\u{00F5}": "o", "\u{00F6}": "o", "\u{00F8}": "o", "\u{014D}": "o",
        "\u{00F9}": "u", "\u{00FA}": "u", "\u{00FB}": "u", "\u{00FC}": "u", "\u{016B}": "u",
        "\u{00E7}": "c", "\u{0107}": "c", "\u{010D}": "c", "\u{00F1}": "n", "\u{0144}": "n", "\u{00FD}": "y", "\u{00FF}": "y",
        "\u{015B}": "s", "\u{0161}": "s", "\u{017E}": "z", "\u{017A}": "z", "\u{0142}": "l", "\u{0111}": "d", "\u{011F}": "g",
        "\u{0121}": "g", "\u{0137}": "k", "\u{0163}": "t", "\u{0165}": "t",
    ]

    /// Levenshtein distance with early exit once `limit` is exceeded (returns `limit + 1` in that case).
    public static func levenshtein(_ a: String, _ b: String, limit: Int = Int.max) -> Int {
        let s = Array(a.unicodeScalars), t = Array(b.unicodeScalars)
        if s.isEmpty { return t.count }
        if t.isEmpty { return s.count }
        if limit < Int.max, abs(s.count - t.count) > limit { return limit + 1 }
        var previous = Array(0...t.count)
        var current = [Int](repeating: 0, count: t.count + 1)
        for i in 1...s.count {
            current[0] = i
            var rowMin = current[0]
            for j in 1...t.count {
                let cost = s[i - 1] == t[j - 1] ? 0 : 1
                current[j] = Swift.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
                rowMin = Swift.min(rowMin, current[j])
            }
            if limit < Int.max, rowMin > limit { return limit + 1 }
            swap(&previous, &current)
        }
        return previous[t.count]
    }

    // MARK: - Brand labels on someone else's domain

    /// A protected brand named by a whole label *below* the registrable domain of a host whose registrable domain
    /// belongs to nobody in the catalog ("zoom.schedule.com", "paypal.secure-login.net", "microsoft.cdn-files.xyz").
    public struct BrandSubdomainMatch: Sendable, Hashable {
        /// Key of the brand the label names.
        public let brandKey: String
        /// The host label that equals the brand name ("zoom").
        public let label: String
        /// Registrable domain that actually owns the host ("schedule.com").
        public let registrableDomain: String

        public init(brandKey: String, label: String, registrableDomain: String) {
            self.brandKey = brandKey
            self.label = label
            self.registrableDomain = registrableDomain
        }
    }

    /// The brand a host puts in front of a *foreign* registrable domain — the "brand.attacker.example" shape that
    /// reads as the brand in a mail client while resolving to someone else's site.
    ///
    /// Unlike `lookalikeMatch` this needs no companion token ("login", "secure", …) and no alteration, because the
    /// brand is a complete DNS label rather than a substring: `zoom.schedule.com`, `apple.id-check.example` and
    /// `chase.acme-cdn.net` all match, which the companion rule deliberately does not do for dictionary-word brands.
    /// Returns nil when
    /// - the registrable domain belongs to any catalog brand (`accounts.google.com` — the brand's own hosts —, and
    ///   `discover.microsoft.com`, one brand's ordinary subdomain on another brand's site),
    /// - the host is a tenant page on multi-tenant brand hosting (`paypal.sharepoint.com`, left to `lookalikeMatch`),
    /// - the host is an IP literal or a URL shortener, or has no label below its registrable domain,
    /// - the matching label is an ordinary subdomain word that merely coincides with a catalog key
    ///   (`genericBrandLabels`: "discover.acme.com", "booking.hotel.example").
    ///
    /// Only brand keys and single-word brand names are compared, so generic labels ("www", "mail", "secure") can
    /// never match — they are not brand names.
    public static func brandSubdomainMatch(for host: String) -> BrandSubdomainMatch? {
        let lower = normalizeHost(host)
        guard !lower.isEmpty, lower.utf16.count <= 253, !isIPLiteral(lower), !isURLShortener(lower) else { return nil }
        let registrable = registrableDomain(of: lower)
        // The brand's own infrastructure, another brand's site and multi-tenant hosting are all out of scope.
        guard brandKey(forRegistrableDomain: registrable) == nil, !multiTenantBrandDomains.contains(registrable) else { return nil }
        if publicSuffixBrandDomains.contains(where: { hostBelongs(lower, under: $0) }) { return nil }

        let labels = lower.split(separator: ".").map(String.init)
        let registrableLabelCount = registrableDomain(of: lower).split(separator: ".").count
        guard labels.count > registrableLabelCount else { return nil }

        for label in labels.dropLast(registrableLabelCount) {
            guard label.count >= 3, !genericBrandLabels.contains(label) else { continue }
            if brandsByKey[label] != nil {
                return BrandSubdomainMatch(brandKey: label, label: label, registrableDomain: registrable)
            }
            if let key = brandKeyBySingleWordName[label] {
                return BrandSubdomainMatch(brandKey: key, label: label, registrableDomain: registrable)
            }
        }
        return nil
    }

    /// Catalog keys and names that are also ordinary subdomain words on unrelated sites: "discover.acme.com" is a
    /// marketing page, "booking.hotel.example" a reservation page, "visa.university.example" an immigration page.
    /// A phishing host that pairs one of these with a companion token ("visa-verify.example") is still a lookalike.
    private static let genericBrandLabels: Set<String> = [
        "discover", "booking", "wise", "visa", "ledger", "steam", "square", "target", "affirm", "blockchain", "meta",
        "max", "prime", "office", "azure", "outlook", "drive",
    ]

    /// The brand whose key or single-word name is exactly `word` (case-insensitive): "paypal" → "paypal",
    /// "icloud" → "apple", "youtube" → "google". Nil for multi-word names and for anything not in the catalog.
    /// Whole-token matching, so it is safe on host labels and on address tokens where a substring search is not.
    public static func brandKey(forBrandName word: String) -> String? {
        let lower = word.lowercased()
        if brandsByKey[lower] != nil { return lower }
        return brandKeyBySingleWordName[lower]
    }

    /// Single-word brand names ("netflix", "icloud", "onedrive", "youtube") → brand key, for whole-label matching.
    /// Multi-word names ("american express", "chase bank") can never be one DNS label and are skipped.
    private static let brandKeyBySingleWordName: [String: String] = {
        var out: [String: String] = [:]
        for brand in brands {
            for name in brand.names where !name.contains(" ") && !name.contains(".") && name.count >= 3 {
                if out[name] == nil { out[name] = brand.key }
            }
        }
        return out
    }()

    // MARK: - Brand mentions

    /// Brand keys whose display names appear in `text` (word-bounded, case-insensitive). Used to link the brand a
    /// mail claims to be from with the domains it actually uses.
    public static func brandsMentioned(in text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        let lower = String(text.prefix(2_000)).lowercased()
        var found: [String] = []
        for brand in brands {
            for name in brand.names where containsWord(name, in: lower) {
                found.append(brand.key)
                break
            }
        }
        return found
    }

    /// Word-bounded containment ("ups" does not match "groups"; "chase" does not match "purchase").
    static func containsWord(_ word: String, in text: String) -> Bool {
        var searchRange = text.startIndex..<text.endIndex
        while let range = text.range(of: word, options: [], range: searchRange) {
            let beforeOK = range.lowerBound == text.startIndex || !isWordCharacter(text[text.index(before: range.lowerBound)])
            let afterOK = range.upperBound == text.endIndex || !isWordCharacter(text[range.upperBound])
            if beforeOK && afterOK { return true }
            guard range.lowerBound < text.endIndex else { break }
            searchRange = text.index(after: range.lowerBound)..<text.endIndex
        }
        return false
    }

    private static func isWordCharacter(_ c: Character) -> Bool {
        c.isLetter || c.isNumber
    }
}
