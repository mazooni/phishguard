import { severityRank, truncate, type CallSeverity, type Speaker, type TranscriptSegment } from "../types.js";

/**
 * Deterministic scam-call signals over the transcript (docs/CALLS.md §6.1). This is the half of the detector
 * that answers instantly, offline and identically on every run: it is what makes the tests deterministic and
 * what the later fully-local variant starts from.
 *
 * Every signal is a set of case-insensitive, word-boundary patterns written for *spoken* transcripts: no
 * reliance on punctuation, numbers may arrive as words, contractions may or may not carry an apostrophe. A
 * signal fires at most once per transcript; the caller's line is preferred over the protected person's when
 * both match, because a scammer's demand weighs more than the victim repeating it (`USER_WEIGHT_FACTOR`). The
 * one exception is `call.user_sharing_sensitive`, which only ever fires on the protected person's lines.
 *
 * Signals that describe a *request* (codes, gift cards, remote access, moving money) are suppressed on a line
 * that is protective advice ("we will never ask you for your code", "do not buy gift cards for anyone who
 * calls you"): a real bank's fraud desk says exactly those words.
 *
 * Gift cards come in two tiers (field report of 2026-09-24: a daughter really is sent for a Starbucks card).
 * `call.gift_cards` (high) is the card's value leaving over the phone — read / send / text / email / photograph
 * the numbers, the code or "the back", scratch it, load or redeem it, pay a fee in gift cards, "they only accept
 * gift cards" — or a bulk "buy gift cards" that names no single card and no errand (`ERRAND_TAIL`: bring them home,
 * on your way home, for the teachers, I'll Venmo you). `call.gift_card_errand` (low) is the plain errand: buy / pick
 * up / grab *a* gift card, from the market, for a birthday, bring it home — or a few of them for the twins. A line
 * that carries a transfer never also counts as an errand (`suppressedBy`); the errand alone leaves the verdict `safe`.
 *
 * The score saturates like PhishCore's `HeuristicAnalyzer`: `1 - Π(1 - weight)`.
 */

export interface CallSignalDefinition {
  id: string;
  /** User-facing, short; also the APNs body fragment (joined by " · "). */
  title: string;
  /** One line for the model prompt and the console. */
  description: string;
  severity: CallSeverity;
  /** Contribution on a caller line, 0…1. */
  weight: number;
}

export interface CallSignal extends CallSignalDefinition {
  /** "Caller said: …" / "You said: …" with ≤ 120 characters of the matching line. */
  detail: string;
  /** Whose line matched. */
  speaker: Speaker;
  /** The segment that matched. */
  segmentId: string;
}

export interface RulesResult {
  signals: CallSignal[];
  /** 0…1, saturating. */
  score: number;
}

/** A signal found on the protected person's line counts this fraction of its caller weight. */
export const USER_WEIGHT_FACTOR = 0.5;
export const MAX_QUOTE_CHARS = 120;

interface SignalSpec extends CallSignalDefinition {
  patterns: RegExp[];
  /** Which speaker's lines the signal is evaluated on (default: both). */
  speakers?: readonly Speaker[];
  /** Skip the line when it reads as protective advice (see `PROTECTIVE_ADVICE`). */
  protectiveGuard?: boolean;
  /** Replaces the quoted line (never quote what the protected person read out). */
  fixedDetail?: string;
  /** Does not fire on a line where this other signal fired (the two are tiers of one thing, one or the other). */
  suppressedBy?: string;
}

const re = (source: string): RegExp => new RegExp(source, "i");

const NUMBER_WORD = "(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)";

/**
 * A line on which a request-type signal must not fire: the speaker is warning *against* the request. Matches
 * "we will never ask you for", "never share your code", "do not buy gift cards", "if anyone asks you for".
 */
const PROTECTIVE_ADVICE: RegExp[] = [
  re("\\b(?:never|will not|won'?t|would never|do not|don'?t|do not ever|does not|doesn'?t)(?: ever)? (?:ask|asks|be asking|request|call (?:you|and ask))\\b"),
  re("\\b(?:never|do not|don'?t|do not ever|should not|shouldn'?t) (?:ever )?(?:share|give(?: out)?|read(?: out)?|provide|buy|purchase|move|transfer|install|download)\\b"),
  re("\\b(?:if|when|whenever) (?:anyone|anybody|someone|somebody|a caller|a stranger) (?:asks?|tells?|calls?|wants?)\\b"),
  re("\\b(?:that|this|it) (?:is|was|sounds like|would be|is probably|might be) (?:a |an )?(?:scam|fraud)\\b"),
];

// MARK: Gift-card vocabulary (the two tiers below share it)

/** A brand whose "… card(s)" is a gift card in a scam ("buy Apple cards", "Google Play cards", "Target gift cards"). */
const GIFT_BRAND = "(?:itunes|i ?tunes|google ?play|steam|apple|amazon|target|walmart|best buy|ebay|sephora|starbucks|home depot|xbox|playstation|nintendo|netflix|roblox|razer)";
/** Prepaid / reload products, which have no errand reading at all. */
const PREPAID_CARD = "(?:prepaid|vanilla|one ?vanilla|reloadable|green ?dot|money ?pak|netspend|bluebird)(?: (?:visa|mastercard|debit|gift|reload|money))? ?cards?\\b";
/** "gift card(s)", "e-gift card(s)", "<brand> (gift) card(s)", "Visa gift card(s)"; `s` fixes the number. */
const cardNoun = (s: string): string =>
  `(?:e-?gift ?${s}|gift ?${s}|${GIFT_BRAND} (?:gift |prepaid |store )?${s}|(?:visa|mastercard|amex|american express) (?:gift|prepaid) ${s})\\b`;
const CARD_SINGULAR = cardNoun("card");
const CARD_PLURAL = cardNoun("cards");
const CARD_ANY = cardNoun("cards?");
/** Cards as a payment method: several of them, or a prepaid product. */
const PAY_CARD = `(?:${CARD_PLURAL}|${PREPAID_CARD})`;
/** One card, however described: "a twenty dollar Target gift card", "the gift card", "one of those Visa gift cards", "a couple of gift cards". */
const ONE_CARD = `(?:(?:a|an|one|the|this|that|another|my|your|her|his|their|our) (?:\\S+ ){0,4}?${CARD_SINGULAR}|(?:one of (?:those|these|the|them|my|your)|a couple of|a pair of) (?:\\S+ ){0,3}?${CARD_PLURAL})`;
/** Not a mention of a card someone already gave: "the gift card I sent you". */
const NOT_A_GIVEN_CARD = "(?! (?:that |which )?(?:i|we|she|he|they|you|mom|dad|grandma|grandpa|your \\w+) (?:sent|gave|mailed|bought|got|left|put|emailed|e-mailed|texted)\\b)";

/** A code that is not a gift card's: a one-time / verification / six-digit code, a zip or gate code, the last four digits. */
const OTP_QUALIFIER =
  "(?:one[- ]time|verification|security|access|authorization|authorisation|confirmation|login|two[- ]factor|2fa|passcode|temporary|otp|text|sms|zip|postal|area|gate|door|garage|phone|account|routing|social|tracking|reference|case|error|promo|discount|coupon|qr|bar|last|first|six|6|four|4|eight|8|three|3)";
/** Up to two words before the code noun, none of them an OTP qualifier. */
const CODE_WORDS = `(?:(?!${OTP_QUALIFIER}\\b)\\S+ ){0,2}?`;
/** "the code we just sent", "the code in the text": an OTP, which `call.otp_or_credentials` owns. */
const NOT_THE_CODE_WE_SENT =
  "(?! (?:we|i|they|you|that (?:we|i|they)) (?:just |have |'ve |had |already )?(?:sent|texted|received|got|emailed|messaged))(?! (?:in|from|on) (?:the |your |that |my )?(?:text|message|sms|phone|email|e-mail|screen|app|notification))";
const HAND_OVER_PRONOUNS = "(?: (?:me|us|him|her|them|it|back|over|out|through|along))*(?: (?:to|over to) (?:me|us|him|her|them|this number|that number|the number))?";
const DETERMINER = "(?:the |that |those |these |all the |all of the |each |every |both |its |their |your |my |a |an |some |two |three )?";
const TRANSMIT_VERB = "(?:send|sends|sending|text|texts|texting|email|e-mail|emails|e-mails|emailing|e-mailing|message|messaging|forward|forwarding|whatsapp)";
const VERBAL_VERB = "(?:read|reads|reading|give|gives|giving|tell|tells|telling|recite)";
const PHOTO = "(?:photos?|pictures?|pics?|images?|snapshots?|screenshots?)";
/** "the back" of a card, not of the house, the car or the line. */
const NOT_A_PHYSICAL_BACK =
  "(?! (?:door|yard|porch|seat|row|garden|gate|entrance|wall|fence|steps|of (?:the |your |my |our )?(?:house|car|truck|van|bus|line|room|building|store|shop|church|letter|envelope|form|page|paper|check|cheque|statement|bill|invoice|receipt|ticket|box|package|photo|picture|jersey|shirt|book|phone|remote|tv))\\b)";
const BUY_VERB = "(?:buy|buying|bought|purchase|purchasing|pick up|picking up|picked up|grab|grabbing|get|getting|got|need|needs|load|loading)";
/** The card's value on its way to the caller: what ends a buy line's errand reading. */
const TRANSFER_TAIL =
  "\\b(?:read|give|tell|send|text|email|e-mail|message|forward|scratch|load|redeem|activate|snap|take)\\b[^.]{0,30}?\\b(?:codes?|pins?|pin numbers?|numbers|digits|(?:on|off|from) the back|silver strip|(?:it|them) (?:onto|on to|into))\\b";
/**
 * What ends a plural "buy gift cards" line's scam reading: the cards come home ("bring them home", "take them to the
 * house"), the errand is on the way ("on your way home"), a gift recipient or occasion is named ("for the teachers",
 * "for Ellie's birthday"), or the caller offers to pay for them ("I'll Venmo you"). A scammer asks none of these ways;
 * a transfer instruction on the same line still fires through the transfer patterns.
 */
const ERRAND_TAIL =
  "(?:\\b(?:bring|bringing|take|taking|carry|leave|drop|hand|keep|wrap|stick|put) (?:them|those|these|it|the cards|the gift cards|everything|all of them|them all)(?: all)? (?:home|back|over|here|there|along|with you|in (?:my|your|the) \\S+|on (?:my|your|the) \\S+|to (?:the house|the party|the office|school|work|me|us|grandma|grandpa|mom|dad|(?:my|your|our|her|his|their) \\S+))\\b" +
  "|\\bon (?:your|the|my|his|her|their) way (?:home|back|over|here|in|out|there)\\b" +
  "|\\bfor (?:\\S+ ){0,3}?(?:birthdays?|graduation|wedding|christmas|xmas|hanukkah|hannukah|easter|thanksgiving|mother'?s day|father'?s day|valentine'?s|anniversary|baby shower|bridal shower|shower|party|presents?|gifts?(?! ?cards?\\b)|stockings?|raffle|fundraiser|bake sale|secret santa|white elephant|teachers?|nurses?|coaches?|babysitter|nanny|sitter|mailman|mail carrier|neighbou?rs?|kids|twins|grandkids|grandchildren|cousins|staff|crew|team|volunteers?|caregivers?|aides?|cleaners?|housekeeper|gardener|dog walker|hairdresser)\\b" +
  "|\\b(?:i|i'll|i will|i can|we'll|we will|mom|dad)(?: will| can|'ll)? (?:pay you back|venmo you|zelle you|give you (?:the )?(?:money|cash))\\b)";
/** "the back" of a card, never "text me back", "when you're back", "the kids back at the house". */
const CARD_BACK = `(?<=\\b(?:the|its|their|each|every|both|all|those|these|of|your|my|card's|cards') )backs?${NOT_A_PHYSICAL_BACK}`;
/** "… on the back", "… off the silver strip", "… under the scratch-off panel". */
const ON_THE_BACK = `(?:on|off|from|under|behind) the (?:silver |grey |gray |scratch[- ]off |scratch )?(?:back|strip|panel|foil|coating)s?\\b${NOT_A_PHYSICAL_BACK}`;

const SIGNAL_SPECS: readonly SignalSpec[] = [
  {
    id: "call.gift_cards",
    title: "Asks for gift cards",
    description:
      "the card's value handed over the phone or gift cards demanded as payment: read / give / send / text / email / photograph the numbers, code or PIN or 'the back', scratch the back, load or redeem it, 'pay the fee in gift cards', 'they only accept gift cards', several cards for a dollar amount; not a plain errand to buy one card and bring it home (that is call.gift_card_errand)",
    severity: "high",
    weight: 0.7,
    protectiveGuard: true,
    patterns: [
      // Bulk: "buy gift cards", "get more gift cards", "buy three Google Play gift cards", "just go buy the gift cards" —
      // no single card named ("a", "one of those", "a couple of" stop the bridge and leave the line to the errand tier)
      // and no errand on the line ("bring them home", "for the teachers", "on your way home": `ERRAND_TAIL`, either side).
      re(
        `(?<!${ERRAND_TAIL}[^.]*)\\b${BUY_VERB}\\b(?: (?!(?:one of|a couple of|a pair of)\\b)\\S+){0,6}? (?:(?:more|some|several|a few|another|extra|additional|multiple|a bunch of|a stack of|two|three|four|five|six|seven|eight|nine|ten|twelve|fifteen|twenty|\\d+) (?:\\S+ ){0,3}?)?${CARD_PLURAL}(?![^.]*${ERRAND_TAIL})`,
      ),
      // Buy one, then hand it over: "buy a gift card and give me the PIN", "buy Apple gift cards, then you read him the numbers".
      re(`\\b${BUY_VERB}\\b[^.]{0,60}?\\b${CARD_ANY}[^.]{0,80}?${TRANSFER_TAIL}`),
      // Read / give / tell the codes, numbers, PINs (plural, or a gift card's): "read me the numbers", "give me the codes now".
      re(
        `\\b${VERBAL_VERB}${HAND_OVER_PRONOUNS} ${DETERMINER}${CODE_WORDS}(?:codes|pins|pin numbers|numbers|digits|claim codes?|redemption codes?|activation codes?|gift ?cards? (?:codes?|numbers?|pins?)|cards (?:codes|numbers|pins)|card codes)\\b${NOT_THE_CODE_WE_SENT}`,
      ),
      // One code, verbally, with the rush that marks it: "give me the code right away", "read me the code now, then …".
      re(
        `\\b${VERBAL_VERB}${HAND_OVER_PRONOUNS} ${DETERMINER}${CODE_WORDS}(?:code|pin|pin number)\\b${NOT_THE_CODE_WE_SENT}[^.]{0,25}?\\b(?:right away|right now|immediately|straight away|now|as soon as|once you|when you|after you|then|first)\\b`,
      ),
      // Send / text / email the code, the numbers, or a photo of the code or the back: an OTP is never emailed.
      re(
        `\\b${TRANSMIT_VERB}${HAND_OVER_PRONOUNS} ${DETERMINER}(?:${PHOTO} of ${DETERMINER})?${CODE_WORDS}(?:codes?|pins?|pin numbers?|numbers|digits|gift ?cards? (?:codes?|numbers?|pins?)|${CARD_BACK}|scratch[- ]off)\\b${NOT_THE_CODE_WE_SENT}`,
      ),
      // "take a photo of the back / the code / the gift card".
      re(
        `\\b(?:take|snap|get)(?: (?:me|us))? (?:a |some |two |three |the )?${PHOTO} of ${DETERMINER}${CODE_WORDS}(?:codes?|pins?|numbers|digits|${CARD_ANY}|${CARD_BACK}|scratch[- ]off)\\b`,
      ),
      // The numbers / code / sixteen-digit number on the back, off the silver strip, from the cards — but not "call the
      // number on the back of your card" and not the three digits on the back (a card's CVV is `otp_or_credentials`).
      re(
        `(?<!\\b(?:call|calling|dial|dialing|dialling|phone|phoning|ring|ringing|use|using) (?:the |that |this )?)(?<!\\b(?:three|3|four|4)[- ])(?<!\\b(?:three|3|four|4)[- ]digit )\\b(?:codes?|pins?|pin numbers?|numbers|digits|(?:(?!(?:three|3|four|4)[- ])\\S+[- ])?digit numbers?|(?:long|whole|full|entire|serial) numbers?) ${ON_THE_BACK}`,
      ),
      // One number, said out loud: "read me the number off the back", "tell me the code on the back of the gift card".
      re(
        `\\b${VERBAL_VERB}${HAND_OVER_PRONOUNS} ${DETERMINER}(?:\\S+ ){0,3}?(?<!\\b(?:three|3|four|4)[- ])(?<!\\b(?:three|3|four|4)[- ]digit )(?:numbers?|codes?|pins?|digits) ${ON_THE_BACK}`,
      ),
      re(`\\b(?:codes?|pins?|pin numbers?|numbers|digits) (?:on|off|from|of) (?:the |that |this |each |every |both |all the |all of the |its |those |these )?(?:\\S+ ){0,2}?(?:${CARD_ANY}|cards\\b)`),
      // Scratch it off.
      re(
        "\\bscratch(?:ed|ing)?(?: (?:it|them|those|these|that|the (?:cards?|labels?)))? off\\b(?! ?(?:tickets?|lottery|lotto|lotteries|games?))|\\bscratch(?:ed|ing)? (?:off )?(?:the |that |those |these |each |every |all the |all of the |its |your )?(?:silver |grey |gray |little |thin )?(?:backs?|strips?|codes?|coatings?|panels?|labels?|stickers?|pins?|foil|scratch[- ]off)\\b",
      ),
      // Rub / scrape / peel the strip or the grey panel, what is under it, the code underneath: a card and nothing else.
      re(
        "\\b(?:rub|rubbed|rubbing|scrape|scraped|scraping|peel|peeled|peeling)(?: (?:it|them|that|this))? off (?:the |that |those |these |each |every |all the |all of the |its |your )?(?:silver |grey |gray |little |thin )?(?:strips?|coatings?|scratch[- ]off)\\b|\\b(?:rub|rubbed|rubbing|scrape|scraped|scraping|peel|peeled|peeling) (?:off )?(?:the |that |those |these |each |every |its |your )?(?:silver|grey|gray) (?:strips?|coatings?|panels?|foil|parts?|areas?|bits?|things?|stuff|labels?|stickers?|squares?|boxe?s?)\\b",
      ),
      re(
        "\\b(?:under|underneath|beneath|behind) the (?:(?:silver|grey|gray|scratch[- ]off|scratch) (?:strips?|coatings?|panels?|foil|parts?|areas?|bits?|things?|stuff|labels?|stickers?|sections?|squares?|boxe?s?)|scratch[- ]off)\\b|\\b(?:codes?|pins?|numbers|digits) (?:underneath|beneath|under (?:it|that|there|them))\\b",
      ),
      // Load / redeem / activate it — remotely, for the caller.
      re(`\\b(?:load|loads|loading|loaded|redeem|redeems|redeeming|redeemed|activate|activates|activating|activated|top up|topping up)(?: (?:the|that|those|these|each|every|all the|all of the|both|its|your|my|it|them))?(?: \\S+){0,2}? ${CARD_ANY}`),
      re("\\b(?:load|loading|loaded|redeem|redeeming|redeemed) (?:the |that |those |these |each |every |all the |all of the |both |its |your |my )?(?:\\S+ )?(?:cards?|codes?)\\b"),
      re("\\b(?:load|redeem|activate)(?:ed|ing)? (?:it|them|the (?:money|funds|cash|balance|value|amount))\\b[^.]{0,40}?\\b(?:read|give|tell|send|text|email|codes?|numbers|pins?|onto|on to|into|to my|to our|to the)\\b"),
      // Gift cards as the payment method: "pay the fine in Google Play cards", "pay with Walmart gift cards", "by purchasing
      // Target gift cards", "send the money back with gift cards", "they only accept gift cards", "the fastest way is with gift cards".
      re(
        `\\b(?:pay|pays|paid|paying|payment|payments|payable|settle|settled|settling|cover|covered|owe|owed|owing)\\b[^.]{0,80}?\\b(?:in|with|by|via|through|using|purchasing|buying|getting|in the form of|only in|only with) (?:\\S+ ){0,3}?${PAY_CARD}`,
      ),
      re(
        `\\b(?:send|sent|sending|wire|return|returning|give back|giving back)\\b(?: \\S+){0,6}? (?:money|funds|payment|amount|balance|difference|dollars|refund|back)\\b[^.]{0,40}?\\b(?:in|with|by|via|through|using|as) (?:\\S+ ){0,2}?${PAY_CARD}`,
      ),
      re(
        `\\b(?:only|just) (?:accepts?|takes?|deals? in|works? with|allows?)(?: payments?)?(?: (?:in|by|with|through|via))? (?:\\S+ ){0,2}?${PAY_CARD}|\\b(?:accepts?|accepting|takes?|taking)(?: payments?)? (?:in|by|with|via|through|only) (?:\\S+ ){0,2}?${PAY_CARD}`,
      ),
      re(
        `\\b(?:way|method|option|means|form of payment) (?:is|would be|will be|has to be|must be|needs to be|'s) (?:with|by|through|using|via|in) (?:\\S+ ){0,2}?${PAY_CARD}|\\b${PAY_CARD} (?:is|are|would be|is going to be|are going to be) the (?:only|fastest|quickest|easiest|best|safest|one|way)\\b`,
      ),
      // A gift card's code or number named at all — unless it is one the speaker sent as a present.
      re(
        `\\b(?:gift ?cards?|${GIFT_BRAND} (?:gift |prepaid |store )?cards?) (?:codes?|numbers?|pins?|pin numbers?|claim codes?|redemption codes?|serial numbers?|digits)\\b(?![^.]{0,25}\\b(?:i|we) (?:sent|emailed|e-mailed|mailed|gave|texted|left) (?:you|her|him|them)\\b)`,
      ),
      // Reload products have no innocent reading.
      re("\\bgreen ?dot\\b|\\bmoney ?pak\\b|\\breload ?it\\b|\\bone ?vanilla\\b|\\bvanilla (?:visa|mastercard|reload)\\b"),
      // Several cards for a dollar amount, plus any transfer verb: "four cards, five hundred dollars each, then send me the codes".
      re(
        "\\b(?:two|three|four|five|six|seven|eight|nine|ten|twelve|fifteen|twenty|\\d+) (?:\\S+ ){0,2}?cards\\b[^.]{0,60}?(?:\\$ ?\\d|\\d[\\d,]* dollars|(?:hundred|thousand|fifty|twenty|forty|sixty|eighty|ninety) dollars|dollars? (?:each|apiece|per card|a piece|on each))[^.]{0,80}?\\b(?:read|give|tell|send|text|email|scratch|load|redeem|activate|codes?|numbers|pins?)\\b|(?:\\$ ?\\d[\\d,]*|\\d[\\d,]* dollars|(?:hundred|thousand|fifty) dollars)\\b[^.]{0,30}?\\b(?:in|of|worth of|on|onto|on each of|each on) (?:\\S+ ){0,3}?cards\\b[^.]{0,80}?\\b(?:read|give|tell|send|text|email|scratch|load|redeem|activate|codes?|numbers|pins?)\\b",
      ),
    ],
  },
  {
    id: "call.gift_card_errand",
    title: "Asks to buy a gift card",
    description:
      "a plain request to buy / pick up / grab / get a gift card, or a few of them for the teachers or the twins (from the market or the pharmacy, for a birthday, bring them home) with no instruction to read, send, photograph, scratch, load or redeem it: an errand, not a scam by itself; the card's value leaving over the phone is call.gift_cards",
    severity: "low",
    weight: 0.15,
    protectiveGuard: true,
    suppressedBy: "call.gift_cards",
    patterns: [
      // "pick up a Starbucks gift card for me", "buy the gift card for your sister", "get me one of those Visa gift cards".
      re(
        `\\b(?:buy|buying|bought|purchase|purchasing|pick up|picking up|picked up|grab|grabbing|grabbed|get|getting|got|gotten|need|needs|needed|want|wants|wanted|bring|bringing|brought|order|ordering|ordered|find)\\b(?: \\S+){0,6}? ${ONE_CARD}${NOT_A_GIVEN_CARD}`,
      ),
      // Several cards on an errand line: "buy two gift cards, one for each of the twins, and bring them home", "grab gift
      // cards for the teachers on your way home". The bulk buy of `call.gift_cards` steps aside on such a line; on a line
      // without the errand (`ERRAND_TAIL`) it fires instead and this tier is suppressed.
      re(
        `\\b(?:buy|buying|bought|purchase|purchasing|pick up|picking up|picked up|grab|grabbing|grabbed|get|getting|got|gotten|need|needs|needed|want|wants|wanted|bring|bringing|brought|order|ordering|ordered|find)\\b(?: \\S+){0,6}? (?:(?:some|several|a few|a handful of|a bunch of|two|three|four|five|six|\\d+) (?:\\S+ ){0,3}?)?${CARD_PLURAL}`,
      ),
      // "a gift card from the pharmacy", "the gift card at the counter".
      re(
        `\\b${ONE_CARD} (?:from|at) (?:the |a |any |that )?(?:market|store|shop|pharmacy|drugstore|drug store|grocery|grocery store|supermarket|mall|walgreens|cvs|target|walmart|costco|rite aid|kroger|safeway|publix|dollar general|best buy|gas station|post office|counter|register)\\b`,
      ),
    ],
  },
  {
    id: "call.wire_or_crypto",
    title: "Asks for a wire transfer or cryptocurrency",
    description: "money to be sent by wire transfer, Western Union / MoneyGram, Bitcoin, a crypto ATM or a crypto wallet",
    severity: "high",
    weight: 0.6,
    protectiveGuard: true,
    patterns: [
      re("\\bwire (?:transfer|the money|the funds|it|them|me|us|some money|\\$?\\d)"),
      re("\\b(?:by|via|through) wire\\b|\\ba wire transfer\\b"),
      re("\\bwestern union\\b|\\bmoney ?gram\\b"),
      re("\\bbit ?coins?\\b|\\bcrypto(?:currency|currencies)?\\b|\\bethereum\\b|\\busdt\\b"),
      re("\\b(?:bitcoin|crypto|coin) (?:atm|machine|kiosk|wallet)\\b"),
      re("\\b(?:invest|investment|trading) (?:platform|account|opportunity|app)\\b.*\\b(?:guaranteed|returns?|profits?|double|triple)\\b"),
      re("\\b(?:guaranteed|guarantee) (?:\\w+ ){0,2}(?:returns?|profits?)\\b"),
    ],
  },
  {
    id: "call.safe_account",
    title: "Says to move money to a \"safe account\"",
    description: "the person is told to move or transfer their money into a new, safe, secure, protected or holding account",
    severity: "high",
    weight: 0.75,
    protectiveGuard: true,
    patterns: [
      re(
        "\\b(?:a|the|our|this|your new|into a|to a) (?:new |special |temporary |government |secure |safe )*(?:safe|secure|protected|holding|temporary|safety) (?:government |federal |treasury )?(?:account|wallet)\\b",
      ),
      re("\\bmove (?:your|the|all your|all of your|those|that) (?:money|funds|savings|cash|balance)\\b"),
      re("\\btransfer (?:your|the|all your|all of your|those|that) (?:money|funds|savings|cash|balance) (?:to|into|over)\\b"),
      re("\\b(?:withdraw|take out) (?:all|the rest of|everything in|your savings|all the money)\\b"),
      re("\\bnew account (?:we|i|that we|that i)(?: have| had)? (?:set up|opened|created|prepared)\\b"),
      re("\\baccount (?:has been|was|is) (?:compromised|hacked|frozen)\\b.*\\b(?:move|transfer|withdraw)\\b"),
    ],
  },
  {
    id: "call.remote_access",
    title: "Asks for remote access to a device",
    description: "AnyDesk, TeamViewer, LogMeIn, UltraViewer, screen sharing or 'let me connect to your computer'",
    severity: "high",
    weight: 0.7,
    protectiveGuard: true,
    patterns: [
      re("\\bany ?desk\\b|\\bteam ?viewer\\b|\\bultra ?viewer\\b|\\blog ?me ?in\\b|\\bquick ?support\\b|\\bgo ?to ?assist\\b|\\bsupremo\\b|\\bconnect ?wise\\b|\\bsplashtop\\b"),
      re("\\bremote (?:access|desktop|support|connection|session|assistance)\\b|\\bremote control (?:of|over|to) your\\b"),
      re("\\b(?:let me|so i can|so we can|i (?:will|'ll|need to|am going to|'m going to)|allow me to|we (?:need|have) to) (?:remotely )?(?:connect|log ?in|log ?on|get|access|take over|take control|see what is|see what's) (?:to |into |on |onto |of )?your (?:computer|pc|laptop|phone|device|screen|desktop|mac|ipad|tablet)\\b"),
      re("\\b(?:give|grant|allow)(?: me| us)? (?:remote )?(?:access|control) (?:to|of|over) your (?:computer|pc|laptop|phone|device|screen|desktop|mac|ipad|tablet)\\b"),
      re("\\bshare your screen\\b|\\bscreen ?shar(?:e|ing)\\b|\\btake control of your\\b"),
      re("\\b(?:install|download|open|type in|go to)(?: \\w+){0,3} (?:app|application|program|software|tool)\\b.*\\b(?:access|connect|control|your screen)\\b"),
    ],
  },
  {
    id: "call.government_threat",
    title: "Threatens arrest or government action",
    description: "IRS, Social Security Administration, Medicare, a warrant, arrest, lawsuit, suspended benefits or a 'case number' against the person",
    severity: "high",
    weight: 0.65,
    patterns: [
      re("\\bi\\.? ?r\\.? ?s\\.?\\b|\\binternal revenue\\b|\\btax (?:office|department|agency|authority)\\b"),
      re("\\bsocial security (?:administration|office|department|agency)\\b|\\bthe ssa\\b"),
      re("\\b(?:a |an |the )?(?:arrest )?warrant\\b"),
      re("\\b(?<!cardiac )(?:arrest|arrested|arresting)\\b(?! of the heart)"),
      re("\\blegal action\\b|\\blawsuit\\b|\\bcriminal (?:charges|case|activity|complaint|investigation)\\b|\\bfederal (?:charges|crime|offense|offence|investigation|agent|agents|officer|officers)\\b"),
      re("\\b(?:suspend|suspended|suspending|cancel|cancelled|canceled|deactivate|deactivated|terminate|terminated|freeze|frozen|block|blocked) (?:your |the )?(?:social security|ssn|benefits|medicare|medicaid|pension|passport|license|licence|driver'?s license)\\b"),
      re("\\b(?:social security|ssn|medicare) (?:number |card |benefits |account )?(?:has been|have been|was|were|is|are|will be|is being|are being) (?:\\w+ ){0,2}(?:suspended|compromised|used|misused|linked|involved|flagged|cancelled|canceled|deactivated|frozen|blocked)\\b"),
      re("\\bback taxes\\b|\\btaxes? (?:owed|due|owing)\\b|\\byou owe (?:the )?(?:irs|government|taxes|back taxes)\\b|\\bunpaid taxes\\b|\\btax (?:fraud|evasion|debt|bill)\\b"),
      re("\\bmedicare (?:fraud|investigation|department|office|services|benefits|card)\\b.*\\b(?:suspend|cancel|new card|verify|confirm|update|fraud|investigation)\\b"),
      re(
        "\\b(?:badge|warrant|docket) (?:number|id|no)\\b|\\b(?:case|complaint) (?:number|id|no)\\b.*\\b(?:arrest|warrant|police|court|legal|federal|fraud|tax|taxes|investigation|charges|irs|officer|agent)\\b|\\b(?:arrest|warrant|police|court|legal|federal|fraud|tax|taxes|investigation|charges|irs|officer|agent)\\b.*\\b(?:case|complaint) (?:number|id|no)\\b",
      ),
      re("\\b(?:sheriff|marshal|marshals|police|officer|deputy|court|judge|prosecutor|attorney general)\\b.*\\b(?:fine|pay|payment|arrest|warrant|jail|court date|summons|contempt)\\b"),
      re("\\bhomeland security\\b|\\bdea\\b|\\bfbi\\b|\\bcustoms and border\\b|\\bimmigration (?:office|officer|services|department)\\b"),
    ],
  },
  {
    id: "call.family_emergency",
    title: "Claims a family member is in trouble",
    description: "a grandchild or relative supposedly in jail, in an accident, needing bail, a lawyer or urgent money; 'don't you recognise my voice'",
    severity: "high",
    weight: 0.55,
    patterns: [
      re("\\bbail\\b|\\bbail (?:money|bond|bondsman)\\b|\\bpost(?:ed|ing)? bail\\b"),
      re("\\bjail\\b|\\bjailed\\b|\\bprison\\b|\\blocked up\\b|\\bin custody\\b|\\bholding cell\\b|\\bdetention (?:center|centre)\\b"),
      re("\\b(?:i|he|she|we|they|your (?:grandson|granddaughter|grandchild|son|daughter|nephew|niece))(?:'ve|'s|'m|'d| was| were| had| have| has| got| am| is| are)(?: \\w+){0,3} (?:in |into )?(?:a |an |the )?(?:car |bad |terrible |serious |little |minor )?(?:accident|crash|wreck|fender bender)\\b"),
      re("\\b(?:i'?m|i am|he'?s|he is|she'?s|she is|they'?re|they are|your (?:grandson|granddaughter|grandchild|son|daughter|nephew|niece) is) in (?:some |big |serious |real |a lot of |a bit of )?trouble\\b"),
      re("\\b(?:need|needs|get|got|hire|hired|pay|pay for|talk to|speak to|call) (?:a |an |the |my |his |her )?(?:lawyer|attorney|public defender)\\b"),
      re("\\b(?:don'?t|do not|do you not|you don'?t|can'?t you) (?:you )?(?:recognize|recognise|know|remember) (?:my voice|who this is|me)\\b"),
      re("\\b(?:it'?s|this is) (?:me|your (?:grandson|granddaughter|grandchild|favorite grandson|favourite grandson|favorite granddaughter|favourite granddaughter))\\b.*\\b(?:trouble|jail|arrested|accident|hospital|money|bail|help me)\\b"),
      re("\\b(?:broke|broken) (?:my|his|her) nose\\b|\\bthat'?s why (?:i|my voice) sounds?\\b"),
      re("\\bin the hospital\\b.*\\b(?:money|pay|send|wire|cards?|cash)\\b"),
      re("\\b(?:kidnap|kidnapped|kidnapping|ransom|hostage)\\b"),
    ],
  },
  {
    id: "call.secrecy",
    title: "Says not to tell anyone or to stay on the line",
    description: "'don't tell anyone', 'keep this between us', 'stay on the line', 'do not hang up', 'don't talk to the bank/police/family/cashier'",
    severity: "high",
    weight: 0.55,
    patterns: [
      re("\\b(?:don'?t|do not|not to|never|can'?t|cannot|must not|mustn'?t|shouldn'?t|should not) (?:\\w+ ){0,2}tell (?:anyone|anybody|nobody|no one|a soul|mom|dad|mum|grandpa|grandma|them|him|her|my parents|your (?:family|kids|children|son|daughter|husband|wife|neighbors|neighbours|friends|bank|caregiver)|the (?:bank|police|cashier|clerk|teller|store|family|cops))\\b"),
      re("\\b(?:don'?t|do not|never|not to) (?:let|want|allow) (?:anyone|anybody|them|him|her|your \\w+) (?:to )?(?:know|find out|hear)\\b"),
      re("\\bkeep (?:this|it|things|the call|our conversation|this call) (?:strictly )?(?:between (?:us|you and me|the two of us)|a secret|secret|quiet|confidential|private|to yourself|just between us)\\b"),
      re("\\b(?:our|a|your|my) (?:little )?secret\\b|\\bsworn to secrecy\\b|\\bgag order\\b|\\bconfidentiality (?:agreement|order)\\b"),
      re("\\bstay on the (?:line|phone|call)\\b|\\bremain on the (?:line|phone|call)\\b|\\bkeep (?:me|us) on the (?:line|phone)\\b"),
      re("\\b(?:don'?t|do not|never|must not|cannot|can'?t|please don'?t) (?:\\w+ ){0,2}hang up\\b|\\bhang up (?:on me|the phone|this call) and\\b.*\\b(?:lose|arrested|warrant|cancel)\\b"),
      re("\\b(?:don'?t|do not|never|not to|do not need to|no need to) (?:\\w+ ){0,2}(?:talk|speak|say anything|mention (?:this|it|anything)|discuss (?:this|it)) (?:to|with) (?:anyone|anybody|the (?:bank|police|cashier|clerk|teller|store|manager|staff)|your (?:family|bank|son|daughter|husband|wife|kids|children|neighbors|neighbours|friends))\\b"),
      re("\\bif (?:they|anyone|anybody|the cashier|the clerk|the teller|someone|somebody) asks?,? (?:just )?(?:say|tell them|tell 'em|it'?s for|the cards? (?:are|is) for)\\b"),
      re("\\b(?:nobody|no one|no body) (?:can|should|needs to|must|has to|is allowed to) (?:know|find out)\\b"),
      re("\\b(?:this is|it'?s) (?:a )?(?:confidential|classified|secret|private|sealed) (?:matter|case|investigation|operation)\\b"),
    ],
  },
  {
    id: "call.urgency",
    title: "Creates urgency",
    description: "'right now', 'immediately', 'within the hour', 'last chance', 'before it's too late', 'time is running out'",
    severity: "medium",
    weight: 0.25,
    patterns: [
      re("\\bright now\\b|\\bright away\\b|\\bimmediately\\b|\\bthis (?:very )?(?:minute|instant|second)\\b|\\bstraight away\\b"),
      re("\\bwithin (?:the next |the |an |one |two |three |twenty[- ]four |24 )?hours?\\b|\\bin the next (?:few |couple of |\\w+ )?(?:minutes|hours)\\b"),
      re("\\bbefore (?:midnight|the end of (?:the |today|business )?day|close of business|it'?s too late|its too late|it is too late|they (?:come|arrive|get here)|the deadline)\\b"),
      re("\\b(?:last|final|only) (?:chance|warning|notice|opportunity|reminder)\\b|\\b(?:time|clock) is (?:running out|ticking)\\b|\\brunning out of time\\b"),
      re("\\burgent(?:ly)?\\b|\\bemergency\\b|\\bact (?:now|fast|quick|quickly|immediately|today)\\b|\\b(?:this|it|that|the matter|the payment|the transfer) (?:can'?t|cannot|can not|must not) (?:afford to )?(?:wait|be delayed)\\b|\\b(?:can'?t|cannot|can not) (?:afford to )?(?:wait|delay) (?:any longer|another|until|till|for)\\b"),
      re("\\b(?:you|we) (?:only )?(?:have|got|'ve got) (?:about |only |just )?(?:\\d+|\\w+) (?:minutes|hours) (?:left|to|before|until)\\b"),
      re("\\btoday (?:or|before|otherwise|or else)\\b|\\bby (?:the end of |end of )?(?:today|tonight|this afternoon|noon|five|5 ?pm|midnight)\\b"),
      re("\\b(?:do|handle|take care of|resolve|fix|sort) (?:this|it) (?:today|now|right now|immediately|straight away)\\b"),
    ],
  },
  {
    id: "call.otp_or_credentials",
    title: "Asks for a code, PIN, password or Social Security number",
    description: "requests a one-time / verification / security code, a PIN, a password, card details or a Social Security number",
    severity: "high",
    weight: 0.65,
    protectiveGuard: true,
    patterns: [
      re("\\b(?:read|tell|give|send|text|confirm|repeat|share|provide|type|enter|say)(?: me| us| it| back| out| to me)? (?:the |that |this |your |a |those |these )?(?:(?:one[- ]time|verification|security|access|authorization|authorisation|confirmation|six[- ]digit|6[- ]digit|four[- ]digit|4[- ]digit|text|sms|login|two[- ]factor|2fa|passcode|temporary|otp) )?(?:code|codes|pin|pin number|password|passwords|passcode|passphrase)\\b"),
      re("\\bone[- ]time (?:code|passcode|password|pin)\\b|\\bverification code\\b|\\bsecurity code\\b|\\baccess code\\b|\\bauthorization code\\b|\\bauthorisation code\\b|\\bconfirmation code\\b|\\b(?:six|6|four|4|eight|8)[- ]digit (?:code|number|pin)\\b|\\btwo[- ]factor\\b|\\b2fa\\b|\\botp\\b"),
      re("\\b(?:the )?code (?:we|i|that was|that we|that i|you) (?:just |have |'ve )?(?:sent|texted|messaged|received|got)\\b|\\b(?:did|have|do) you (?:get|receive|got|see|have) (?:a|the|that|my) (?:code|text|message)\\b"),
      re("\\byour (?:online )?(?:banking )?(?:pin|pin number|password|passwords|passcode|login|log in|user ?name|username and password|account password|email password|apple id password|icloud password)\\b"),
      re("\\bsocial security number\\b|\\bsocial security (?:card )?number\\b|\\b(?:last|full) (?:four|4) (?:digits )?of your social\\b|\\byour social\\b|\\bssn\\b|\\bsocial (?:security )?(?:number|card|digits)\\b"),
      re("\\bmother'?s maiden name\\b|\\bmaiden name\\b"),
      re("\\b(?:card|debit card|credit card|account|routing|bank account) number\\b|\\bnumber on (?:the front|the back|your card)\\b|\\b(?:three|3)[- ]digit (?:code|number|security)\\b|\\bcvv\\b|\\bcvc\\b"),
      re("\\bconfirm (?:your )?(?:identity|account|details|information) (?:by|with) (?:reading|giving|telling)\\b"),
    ],
  },
  {
    id: "call.prize_or_lottery",
    title: "Announces a prize, lottery or sweepstakes",
    description: "'you have won', lottery, sweepstakes, jackpot, a prize or winnings that need a processing / delivery / claim fee",
    severity: "high",
    weight: 0.55,
    patterns: [
      // "you've been picked", not "you've picked up the gift card".
      re("\\byou(?:'ve| have|'re| are)(?: been)? (?:selected|won|chosen|picked(?! (?:up|out)\\b)|the winner|our winner|the lucky winner|a winner)\\b|\\bcongratulations\\b.*\\b(?:won|winner|prize|selected|chosen)\\b"),
      re("\\blottery\\b|\\bsweepstakes?\\b|\\bjackpot\\b|\\bpublishers? clearing house\\b|\\bmega ?millions\\b|\\bpower ?ball\\b|\\bprize (?:draw|money|patrol|department)\\b|\\bcash prize\\b|\\bgrand prize\\b"),
      re("\\b(?:your|the cash|the grand|a cash|a grand|a huge|a big) prize\\b|\\bwinnings\\b|\\bclaim your (?:prize|winnings|reward|money|award|gift)\\b|\\bprize (?:is|of) \\$?\\d"),
      re(
        "\\b(?:prize|prizes|winnings|won|winner|lottery|sweepstakes|jackpot|reward|award|grant)\\b.*\\b(?:processing|handling|release|claim|claiming|activation|redemption|customs|registration|delivery|shipping|tax|taxes|insurance) fees?\\b|\\b(?:processing|handling|release|claim|claiming|activation|redemption|customs|registration|delivery|shipping) fees?\\b.*\\b(?:prize|prizes|winnings|won|winner|lottery|sweepstakes|jackpot|reward|award)\\b",
      ),
      re("\\bfree (?:cruise|vacation|holiday|trip|car|gift)\\b|\\byou (?:have )?(?:qualif(?:y|ied)|are eligible) for a (?:free|cash|\\$)\\b"),
    ],
  },
  {
    id: "call.tech_support",
    title: "Tech-support or refund pretext",
    description: "a virus, a hacked or compromised computer, 'Microsoft/Apple/Norton support', a technician, a refund you are owed or an accidental overpayment",
    severity: "high",
    weight: 0.5,
    patterns: [
      re("\\bmalware\\b|\\bspyware\\b|\\btrojan\\b|\\bransomware\\b|\\bhack(?:ed|ers?|ing)\\b"),
      re(
        "\\bvirus(?:es)?\\b.*\\b(?:computer|pc|laptop|device|mac|phone|windows|system|files?|network|router|remove|removed|clean|scan|technician|support)\\b|\\b(?:computer|pc|laptop|device|mac|phone|windows|system|files?|network|router)\\b.*\\bvirus(?:es)?\\b",
      ),
      re(
        "\\b(?:computer|pc|laptop|device|mac|phone|windows|system|files?|network|router|ip address) (?:is|has been|was|got|are|have been) infected\\b|\\binfected with (?:a |the |some )?(?:virus|malware|trojan|spyware|ransomware)\\b",
      ),
      re(
        "\\byour (?:computer|pc|laptop|device|mac|ip address|router|network|windows|internet) (?:has been|is being|was|has|is|got|have been|will be) (?:\\w+ )?(?:compromised|hacked|infected|sending|showing|flagged|generating|attacked|breached|at risk|in danger|exposed|blocked|suspended|disconnected)\\b",
      ),
      re("\\b(?:microsoft|windows|apple|mac|norton|mcafee|geek squad|dell|hp|google|amazon|paypal|netflix) (?:support|technician|technical|security|tech|department|team|help ?desk|service center)\\b"),
      re("\\b(?:microsoft|windows|apple) (?:security|defender|alert|warning|license|licence|subscription)\\b|\\bmicrosoft\\b.*\\b(?:computer|alert|security|warning|technician|license|licence)\\b"),
      re("\\btech(?:nical)? (?:support|department|team|help)\\b|\\btechnician\\b|\\bcertified (?:engineer|technician)\\b|\\bhelp ?desk\\b"),
      re("\\b(?:security|suspicious|unusual|unauthorized|unauthorised) (?:alert|activity|access|login|log in|sign in|attempts?) (?:on|from|to) your (?:computer|device|account|network|ip)\\b"),
      re("\\b(?:compromised|breached|been hacked|has been hacked|sending (?:out )?(?:spam|viruses|errors|error messages))\\b"),
      re("\\b(?:license|licence|subscription|antivirus|protection plan|warranty) (?:has |was |is |will be )?(?:expired|expiring|renewed|auto[- ]renewed|renewing|about to expire|cancelled|canceled)\\b"),
      re("\\brefund (?:department|team|specialist|process|of \\$?\\d|for \\$?\\d)\\b|\\b(?:owed|owe you|due|entitled to|eligible for|qualify for) (?:a |the |your |an? full |a partial )?refund\\b"),
      re("\\b(?:accidentally|mistakenly|by mistake) (?:refunded|sent|transferred|deposited|credited|overpaid)\\b|\\btoo much money\\b|\\bsent you (?:too much|extra|more than)\\b|\\boverpaid\\b|\\bextra (?:\\$|money|amount|zero)\\b"),
      re(
        "\\b\\$?\\d[\\d,]*(?:\\.\\d+)? (?:dollars )?(?:was|has been|will be|were|got|is being|is about to be) (?:charged|deducted|debited|taken|billed|withdrawn)\\b.*\\b(?:unless|refund|reverse|to (?:stop|cancel) (?:the|this|your|it))\\b",
      ),
      re("\\berror (?:messages?|reports?|codes?)\\b.*\\b(?:computer|device|windows|mac)\\b|\\b(?:computer|device|windows|mac)\\b.*\\berror (?:messages?|reports?|codes?)\\b"),
    ],
  },
  {
    id: "call.impersonation",
    title: "Claims to be from a bank, a company or the government",
    description: "'this is … from your bank / Chase / Amazon / Apple / Microsoft / the fraud department / the government / a courier'",
    severity: "medium",
    weight: 0.25,
    patterns: [
      re("\\b(?:this is|i'?m|i am|my name is|you'?re speaking with|you are speaking with|calling|we'?re calling|we are calling|i'?m calling|i am calling)(?: \\w+){0,4}? (?:from|with|on behalf of|representing) (?:the |your )?(?:bank|chase|wells fargo|bank of america|citi|citibank|capital one|us bank|pnc|td bank|truist|barclays|hsbc|santander|lloyds|natwest|halifax|nationwide|credit union|amazon|apple|microsoft|google|paypal|ebay|facebook|meta|netflix|the government|social security|medicare|medicaid|the irs|irs|revenue|treasury|fraud department|security department|fraud team|security team|fraud prevention|billing department|visa|mastercard|american express|amex|discover|fedex|ups|usps|dhl|the post office|royal mail|verizon|at ?& ?t|t-mobile|comcast|xfinity|spectrum|geek squad|norton|mcafee|the sheriff|the sheriff'?s office|the police|the court|the courthouse|customs|border|immigration|the embassy|the consulate|the (?:electric|power|gas|water|utility) company|publishers clearing house)\\b"),
      re("\\b(?:the |your |our )?(?:fraud|security|billing|refund|collections|legal|investigation|compliance|verification|loss prevention) (?:department|team|unit|division|office|specialist|desk|bureau)\\b"),
      re("\\b(?:agent|officer|investigator|technician|badge) (?:number|id) (?:is )?[a-z]?\\d"),
      re("\\b(?:on behalf of|representing) (?:the )?(?:bank|government|court|irs|federal|state|county|city|police|sheriff)\\b"),
      re("\\bcalling from (?:the )?(?:bank|government|court|irs|federal|state|county|city|police|sheriff|amazon|apple|microsoft|google|paypal|medicare|social security)\\b"),
    ],
  },
  {
    id: "call.payment_pressure",
    title: "Pressures for a payment, fee or fine",
    description: "'pay today', 'or else', a fee, fine, penalty, overdue balance, a service to be cut off unless paid, payment in cash / cards / crypto",
    severity: "medium",
    weight: 0.4,
    patterns: [
      re("\\bpay (?:today|now|immediately|right now|right away|tonight|within|before|in full|the (?:fee|fine|penalty|balance|amount|full amount|outstanding)|a (?:fee|fine|penalty)|this (?:fee|fine|penalty|amount))\\b"),
      re("\\bor else\\b|\\botherwise (?:you|we|they|the|your)\\b.*\\b(?:arrest|warrant|cancel|suspend|disconnect|shut off|cut off|lose|charged|fine|police|court|jail)\\b|\\bif you (?:don'?t|do not|fail to|refuse to) (?:pay|send|make the payment|comply|cooperate)\\b|\\bunless you pay\\b"),
      re("\\b(?:pay|send|cover|owe|owed|owes|settle|clear) (?:the|a|this|that|an|your|some|all) (?:\\w+ )?(?:fee|fees|fine|fines|penalty|penalties|taxes|debt|outstanding|arrears)\\b"),
      re("\\b(?:you|we|they) (?:have|need|are required|are going|will have) to (?:pay|make a payment|send|settle)\\b|\\b(?:payment|fee|fine|penalty) (?:is|are) (?:due|required|mandatory|overdue)\\b"),
      re("\\b(?:make|send|submit) (?:a|the|your) payment (?:today|now|immediately|right away|right now|tonight|within|before|by|of)\\b"),
      re("\\b(?:pay|payment|paid) (?:in|by|with|using|via|through) (?:cash|gift ?cards?|bitcoin|crypto|prepaid|a money order|money order|western union|moneygram)\\b"),
      re("\\b(?:penalty|fine|late fee|processing fee|surcharge) of \\$?\\d|\\bfine of\\b|\\b(?:legal|court|attorney|lawyer|filing) fees?\\b|\\bcollections? (?:agency|department|team|call)\\b|\\bdebt collector\\b"),
      re("\\boverdue (?:balance|payment|bill|invoice|amount|account)\\b|\\bpast due\\b|\\bfinal (?:demand|notice)\\b|\\b(?:unpaid|outstanding) (?:bill|balance|invoice|amount|fine|fees?)\\b"),
      re("\\b(?:will be|gets|get|is going to be|are going to be|is about to be|about to be|be) (?:disconnected|shut off|cut off|suspended|terminated|cancelled|canceled|deactivated|closed|turned off|blocked|frozen) (?:unless|if|today|tonight|within|in the next|in \\w+ (?:minutes|hours)|by)\\b"),
    ],
  },
  {
    id: "call.callback_refusal",
    title: "Discourages hanging up or calling back",
    description: "'you can't call back', 'this number won't work', 'no need to check with your bank', 'if you hang up we cannot help you'",
    severity: "high",
    weight: 0.5,
    patterns: [
      re("\\byou (?:can'?t|cannot|can not|won'?t|will not|are unable to|are not able to|don'?t need to|do not need to|shouldn'?t|should not|must not|mustn'?t) (?:\\w+ ){0,2}(?:call|ring|phone|contact|reach)(?: me| us| them| this number| this line)? back\\b"),
      re("\\b(?:there'?s|there is) no (?:way|number) to (?:call|reach|contact)(?: me| us)? back\\b|\\b(?:we|i) (?:can'?t|cannot|won'?t|will not|do not|don'?t) (?:accept|take|receive) (?:incoming |any |return )?calls\\b|\\b(?:incoming|return) calls are (?:not accepted|blocked|disabled)\\b"),
      re("\\b(?:this|that|the|our|my) (?:phone )?(?:number|line|extension) (?:won'?t|will not|doesn'?t|does not|can'?t|cannot|isn'?t going to|is not going to|might not|may not) (?:work|go through|connect|be reachable|be answered|accept|show|ring|be available)\\b"),
      re("\\b(?:no need|don'?t need|do not need|not necessary|there'?s no need|there is no need|no reason|don'?t bother|do not bother|don'?t waste time|you don'?t have) to (?:call|check with|verify with|contact|go to|visit|talk to|speak to|confirm with|hang up and call|ring) (?:your bank|the bank|anyone|anybody|them|the number on|the branch|your branch|the police|your family|customer service|the real|the official)\\b"),
      re("\\b(?:if|once|when|should) you hang up\\b.*\\b(?:lose|lost|cancel|cancelled|canceled|arrest|arrested|warrant|too late|cannot help|can'?t help|won'?t be able|will not be able|no longer|expire|expires|void|forfeit|police|frozen|freeze)\\b|\\bhang up (?:now )?and (?:you|we|they|the)\\b.*\\b(?:lose|arrest|warrant|cancel|too late)\\b"),
      re("\\b(?:you|we|they) (?:will|would|'ll|are going to) lose (?:the|this|your|our) (?:case|line|connection|money|chance|opportunity|protection|refund|claim|prize|winnings|spot)\\b"),
      re("\\b(?:only|just) (?:through|on|via|from|at) (?:this|that|my|our) (?:number|line|extension|phone)\\b|\\b(?:don'?t|do not) (?:try|attempt) (?:to )?(?:call|calling|phon)(?:ing)? (?:me |us )?back\\b"),
      re("\\b(?:don'?t|do not|never) (?:go|walk) (?:to|into) (?:the|a|your) (?:bank|branch|police|station)\\b|\\b(?:don'?t|do not) (?:call|contact|talk to|speak to) (?:your|the) (?:bank|branch|police|family|son|daughter|husband|wife)\\b"),
    ],
  },
  {
    id: "call.user_sharing_sensitive",
    title: "You read out a code or card number",
    description: "the protected person read out a long run of digits, a code, a password or the number on a card",
    severity: "high",
    weight: 0.8,
    speakers: ["user"],
    fixedDetail: "You said: something that sounds like a card number, a code or a password was read out.",
    patterns: [
      re("(?:\\d[\\s,.-]*){8,}"),
      re(`\\b(?:${NUMBER_WORD}[\\s,.-]+){7,}${NUMBER_WORD}\\b`),
      re("\\bmy (?:(?:one[- ]time |verification |security |pin |access |six[- ]digit |6[- ]digit )?(?:code|pin|pin number|password|passcode|passphrase|social|social security(?: number)?|account number|card number|routing number|date of birth|mother'?s maiden name|maiden name)) (?:is|was|would be|number is)\\b"),
      re("\\b(?:the|that|this) (?:code|number|numbers|pin|password) (?:on|from|off|at) (?:the |my )?(?:back of the |front of the )?(?:card|text|message|phone|screen|email)\\b"),
      // Six or more digits: a one-time code, never a zip code or a gate code.
      re(`\\b(?:here'?s|here is|okay it'?s|ok it'?s|it'?s|that'?s|it says|it reads|the code is|the number is|the pin is|the password is|my code is)(?: \\w+){0,2} (?:\\d{6,}|(?:${NUMBER_WORD}[\\s,-]+){5,}${NUMBER_WORD})\\b`),
      re(`\\b(?:code|pin|password|number|numbers) (?:is|are|says|reads|would be)[:,]? (?:\\d{6,}|(?:${NUMBER_WORD}[\\s,-]+){5,}${NUMBER_WORD})\\b`),
    ],
  },
];

/** id → definition, in catalog order (prompts and tests). */
export const SIGNAL_CATALOG: ReadonlyMap<string, CallSignalDefinition> = new Map(
  SIGNAL_SPECS.map((spec) => [
    spec.id,
    { id: spec.id, title: spec.title, description: spec.description, severity: spec.severity, weight: spec.weight },
  ]),
);

export const SIGNAL_IDS: readonly string[] = SIGNAL_SPECS.map((spec) => spec.id);

export function signalDefinition(id: string): CallSignalDefinition | undefined {
  return SIGNAL_CATALOG.get(id);
}

/** `1 - Π(1 - w)`: several weak signals add up, a strong one is never diluted. */
export function saturatingScore(weights: readonly number[]): number {
  let survival = 1;
  for (const weight of weights) survival *= 1 - Math.min(1, Math.max(0, weight));
  const score = 1 - survival;
  return Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0;
}

/** Spoken transcripts arrive with or without punctuation and curly quotes; patterns are written for this form. */
export function normalizeLine(text: string): string {
  return text
    .replace(/[‘’ʼ]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/[\p{Cc}]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Digit runs of four or more are masked before a line is quoted into a reason (never persist a code). */
export function maskDigits(text: string): string {
  return text.replace(/\d(?:[\s-]?\d){3,}/g, (run) => run.replace(/\d/g, "•"));
}

function isProtectiveAdvice(line: string): boolean {
  return PROTECTIVE_ADVICE.some((pattern) => pattern.test(line));
}

/** ≤ `MAX_QUOTE_CHARS` of the line, centred on the match when the line is longer than that. */
function quote(line: string, matchIndex: number, matchLength: number): string {
  if (line.length <= MAX_QUOTE_CHARS) return line;
  const half = Math.floor((MAX_QUOTE_CHARS - matchLength) / 2);
  let start = Math.max(0, matchIndex - half);
  let end = Math.min(line.length, start + MAX_QUOTE_CHARS);
  if (end - start < MAX_QUOTE_CHARS) start = Math.max(0, end - MAX_QUOTE_CHARS);
  // Snap to word boundaries so the quote does not start or end mid-word.
  if (start > 0) {
    const space = line.indexOf(" ", start);
    if (space >= 0 && space < matchIndex) start = space + 1;
  }
  if (end < line.length) {
    const space = line.lastIndexOf(" ", end);
    if (space > matchIndex + matchLength) end = space;
  }
  const text = line.slice(start, end).trim();
  return `${start > 0 ? "…" : ""}${text}${end < line.length ? "…" : ""}`;
}

interface Match {
  spec: SignalSpec;
  speaker: Speaker;
  segmentId: string;
  detail: string;
}

/**
 * Runs every signal over the final segments. Returns the signals found (catalog order) and the saturating
 * score. Partials are ignored: they are display-only (docs/CALLS.md §4). One-shot form of `TranscriptAnalyzer`.
 */
export function analyzeTranscript(segments: readonly TranscriptSegment[]): RulesResult {
  return new TranscriptAnalyzer().analyze(segments);
}

interface SegmentMatches {
  text: string;
  speaker: Speaker;
  /** spec id → the match on this line, for the specs that fired. */
  matches: Map<string, Match>;
}

/**
 * `analyzeTranscript` with the regex work done once per segment: matches are cached by segment id (re-run when a
 * final's text or speaker changes) and only the merge across segments — a caller line beats a user line, else the
 * first occurrence stands — runs on every call, so a 2000-segment call costs O(n) map lookups per new final
 * instead of O(n) regex passes. Segments that left the window (`MAX_SEGMENTS`) are forgotten on the next call.
 * One instance per session (the detector keeps it in its per-session state).
 */
export class TranscriptAnalyzer {
  private readonly cache = new Map<string, SegmentMatches>();

  /** Final segments whose matches are cached (tests). */
  get cachedCount(): number {
    return this.cache.size;
  }

  analyze(segments: readonly TranscriptSegment[]): RulesResult {
    const best = new Map<string, Match>();
    const seen = new Set<string>();
    for (const segment of segments) {
      if (!segment.final) continue;
      seen.add(segment.id);
      let entry = this.cache.get(segment.id);
      if (!entry || entry.text !== segment.text || entry.speaker !== segment.speaker) {
        entry = { text: segment.text, speaker: segment.speaker, matches: matchSegment(segment) };
        this.cache.set(segment.id, entry);
      }
      for (const [id, match] of entry.matches) {
        const existing = best.get(id);
        // A caller line always beats a user line; otherwise the first occurrence stands.
        if (existing && (existing.speaker === "caller" || match.speaker === "user")) continue;
        best.set(id, match);
      }
    }
    if (this.cache.size > seen.size) {
      for (const id of this.cache.keys()) if (!seen.has(id)) this.cache.delete(id);
    }
    return collectSignals(best);
  }
}

/** Every signal that fires on one final segment (its own line only). */
function matchSegment(segment: TranscriptSegment): Map<string, Match> {
  const matches = new Map<string, Match>();
  const line = normalizeLine(segment.text);
  if (!line) return matches;
  const protective = isProtectiveAdvice(line);
  for (const spec of SIGNAL_SPECS) {
    if (spec.speakers && !spec.speakers.includes(segment.speaker)) continue;
    if (spec.protectiveGuard && protective) continue;
    const found = firstMatch(spec, line);
    if (!found) continue;
    const prefix = segment.speaker === "caller" ? "Caller said: " : "You said: ";
    const detail =
      spec.fixedDetail ?? `${prefix}“${truncate(maskDigits(quote(line, found.index, found.length)), MAX_QUOTE_CHARS + 2)}”`;
    matches.set(spec.id, { spec, speaker: segment.speaker, segmentId: segment.id, detail });
  }
  // A tiered pair fires as one or the other on a line: the errand reading of a gift card dies with a transfer on it.
  for (const spec of SIGNAL_SPECS) {
    if (spec.suppressedBy && matches.has(spec.suppressedBy)) matches.delete(spec.id);
  }
  return matches;
}

function collectSignals(best: ReadonlyMap<string, Match>): RulesResult {
  const signals: CallSignal[] = [];
  for (const spec of SIGNAL_SPECS) {
    const match = best.get(spec.id);
    if (!match) continue;
    const weight =
      match.speaker === "caller" || spec.speakers?.length === 1 ? spec.weight : round4(spec.weight * USER_WEIGHT_FACTOR);
    signals.push({
      id: spec.id,
      title: spec.title,
      description: spec.description,
      severity: spec.severity,
      weight,
      detail: match.detail,
      speaker: match.speaker,
      segmentId: match.segmentId,
    });
  }
  signals.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.weight - a.weight);
  return { signals, score: saturatingScore(signals.map((signal) => signal.weight)) };
}

function firstMatch(spec: SignalSpec, line: string): { index: number; length: number } | undefined {
  let best: { index: number; length: number } | undefined;
  for (const pattern of spec.patterns) {
    const match = pattern.exec(line);
    if (!match) continue;
    if (!best || match.index < best.index) best = { index: match.index, length: match[0].length };
  }
  return best;
}

function round4(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

/** True when at least one signal of the given severity or worse is present. */
export function hasSignalAtLeast(signals: readonly CallSignal[], severity: CallSeverity): boolean {
  const floor = severityRank(severity);
  return signals.some((signal) => severityRank(signal.severity) >= floor);
}
