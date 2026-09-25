import { describe, expect, it } from "vitest";

import {
  MAX_QUOTE_CHARS,
  SIGNAL_CATALOG,
  SIGNAL_IDS,
  USER_WEIGHT_FACTOR,
  analyzeTranscript,
  hasSignalAtLeast,
  maskDigits,
  normalizeLine,
  saturatingScore,
  type RulesResult,
} from "../../src/calls/scoring/rules.js";
import type { Speaker, TranscriptSegment } from "../../src/calls/types.js";

type Line = [Speaker, string];

let counter = 0;
function segment(speaker: Speaker, text: string, final = true): TranscriptSegment {
  counter += 1;
  return { id: `${speaker}-${counter}`, speaker, text, atMs: counter * 1000, final };
}

function run(lines: Line[]): RulesResult {
  return analyzeTranscript(lines.map(([speaker, text]) => segment(speaker, text)));
}

function ids(result: RulesResult): string[] {
  return result.signals.map((signal) => signal.id);
}

function caller(text: string): RulesResult {
  return run([["caller", text]]);
}

const EXPECTED_IDS = [
  "call.gift_cards",
  "call.gift_card_errand",
  "call.wire_or_crypto",
  "call.safe_account",
  "call.remote_access",
  "call.government_threat",
  "call.family_emergency",
  "call.secrecy",
  "call.urgency",
  "call.otp_or_credentials",
  "call.prize_or_lottery",
  "call.tech_support",
  "call.impersonation",
  "call.payment_pressure",
  "call.callback_refusal",
  "call.user_sharing_sensitive",
];

describe("signal catalog", () => {
  it("lists exactly the ids of docs/CALLS.md §6.1", () => {
    expect([...SIGNAL_IDS].sort()).toEqual([...EXPECTED_IDS].sort());
    expect(SIGNAL_CATALOG.size).toBe(EXPECTED_IDS.length);
  });

  it("gives every signal a title, a description, a severity and a weight in (0, 1]", () => {
    for (const definition of SIGNAL_CATALOG.values()) {
      expect(definition.title.length).toBeGreaterThan(3);
      expect(definition.description.length).toBeGreaterThan(10);
      expect(["info", "low", "medium", "high"]).toContain(definition.severity);
      expect(definition.weight).toBeGreaterThan(0);
      expect(definition.weight).toBeLessThanOrEqual(1);
    }
  });

  it("marks the protected person reading out a code as high severity", () => {
    expect(SIGNAL_CATALOG.get("call.user_sharing_sensitive")?.severity).toBe("high");
  });
});

describe("each signal: positive and negative", () => {
  const cases: { id: string; positive: string; negative: string }[] = [
    { id: "call.gift_cards", positive: "Go to the store and buy three Google Play gift cards", negative: "I bought her a birthday card and some flowers" },
    {
      id: "call.gift_card_errand",
      positive: "Can you pick up a Starbucks gift card for me on your way home",
      negative: "Did you get the gift card I sent you for your birthday",
    },
    {
      id: "call.wire_or_crypto",
      positive: "Send the money by wire transfer to this account",
      negative: "The electrician needs to replace the wire in the kitchen",
    },
    {
      id: "call.safe_account",
      positive: "You need to move your money into a safe account right away",
      negative: "Your account is safe, nothing was charged",
    },
    { id: "call.remote_access", positive: "Download AnyDesk so I can connect to your computer", negative: "I will email you the photos from my computer" },
    { id: "call.government_threat", positive: "There is a warrant for your arrest for unpaid taxes", negative: "The tax refund arrived in the mail yesterday" },
    {
      id: "call.family_emergency",
      positive: "Grandma it's me, I'm in trouble and I need bail money",
      negative: "Grandma it's me, I'm calling to wish you a happy birthday",
    },
    { id: "call.secrecy", positive: "Don't tell anyone about this, keep it between us", negative: "Tell everyone at church I said hello" },
    { id: "call.urgency", positive: "You must do this right now, within the hour", negative: "There is no rush, call me whenever you have time" },
    {
      id: "call.otp_or_credentials",
      positive: "Read me the verification code we just sent to your phone",
      negative: "What is the zip code for your address",
    },
    {
      id: "call.prize_or_lottery",
      positive: "Congratulations, you have won the grand prize in our sweepstakes",
      negative: "The kids won their soccer game on Saturday",
    },
    {
      id: "call.tech_support",
      positive: "This is Microsoft support, your computer has been infected with a virus",
      negative: "My grandson fixed my computer last weekend",
    },
    {
      id: "call.impersonation",
      positive: "This is Michael calling from the Amazon fraud department",
      negative: "This is Linda from next door, do you need anything from the store",
    },
    {
      id: "call.payment_pressure",
      positive: "You have to pay the fine today or else the police will come",
      negative: "The invoice was paid last month, thank you",
    },
    { id: "call.callback_refusal", positive: "You can't call back on this number, it won't work", negative: "Call me back on this number whenever you like" },
  ];

  it.each(cases)("$id fires on a matching caller line", ({ id, positive }) => {
    expect(ids(caller(positive))).toContain(id);
  });

  it.each(cases)("$id stays quiet on a look-alike benign line", ({ id, negative }) => {
    expect(ids(caller(negative))).not.toContain(id);
  });

  it("call.user_sharing_sensitive fires when the protected person reads out a code", () => {
    expect(ids(run([["user", "My code is four seven two one nine eight"]]))).toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "Okay, the code is 482913"]]))).toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "It's 4111 1111 1111 1111"]]))).toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "My password is sunflower"]]))).toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "The numbers on the back of the card are 7 3 3 9"]]))).toContain("call.user_sharing_sensitive");
  });

  it("call.user_sharing_sensitive ignores a zip code, a gate code and the caller's own digits", () => {
    expect(ids(run([["user", "My zip code is nine zero two one zero"]]))).not.toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "The gate code is two five one seven, come on up"]]))).not.toContain("call.user_sharing_sensitive");
    expect(ids(run([["caller", "Call us back at 1 800 555 0199 4321 any time"]]))).not.toContain("call.user_sharing_sensitive");
  });
});

describe("speaker weighting", () => {
  it("weighs a user line at half the caller weight and prefers the caller occurrence", () => {
    const line = "buy gift cards and read me the numbers";
    const spec = SIGNAL_CATALOG.get("call.gift_cards")!;
    const fromUser = run([["user", line]]);
    expect(fromUser.signals[0]?.weight).toBeCloseTo(spec.weight * USER_WEIGHT_FACTOR, 5);
    expect(fromUser.signals[0]?.detail.startsWith("You said: ")).toBe(true);

    const fromBoth = run([
      ["user", line],
      ["caller", line],
    ]);
    const signal = fromBoth.signals.find((entry) => entry.id === "call.gift_cards")!;
    expect(signal.weight).toBe(spec.weight);
    expect(signal.speaker).toBe("caller");
    expect(signal.detail.startsWith("Caller said: ")).toBe(true);
  });

  it("gives call.user_sharing_sensitive its full weight on the user's line", () => {
    const result = run([["user", "the code is 123456"]]);
    expect(result.signals[0]?.weight).toBe(SIGNAL_CATALOG.get("call.user_sharing_sensitive")!.weight);
  });
});

describe("protective advice", () => {
  it("does not count a bank warning against codes and gift cards as a request", () => {
    const warning = run([
      ["caller", "We will never ask you for your PIN or a verification code, and never buy gift cards for anyone who calls."],
    ]);
    expect(ids(warning)).not.toContain("call.otp_or_credentials");
    expect(ids(warning)).not.toContain("call.gift_cards");
  });

  it("still fires on the same words when they are a demand", () => {
    expect(ids(caller("Read me the verification code and buy gift cards."))).toEqual(
      expect.arrayContaining(["call.otp_or_credentials", "call.gift_cards"]),
    );
  });

  it("does not let secrecy talk mask a demand on the same line", () => {
    expect(ids(caller("Don't tell anyone, just go buy the gift cards."))).toEqual(expect.arrayContaining(["call.secrecy", "call.gift_cards"]));
  });
});

/**
 * Field report, 2026-09-24: "I want you to pick up a Starbucks gift card" on a real family call was flagged and the
 * in-call warning spoken — and the owner's mother really does send him for gift cards. A card bought and brought
 * home is an errand (`call.gift_card_errand`, low; the verdict stays `safe`, `low` at most with a hurry in it). The
 * scam is the card's value leaving over the phone (`call.gift_cards`, high). A line carries one of the two, never both.
 */
describe("gift cards: an errand is not a transfer", () => {
  const errands: { line: string; hurried?: boolean }[] = [
    { line: "I want you to pick up a Starbucks gift card for me" },
    { line: "Can you pick up a Starbucks gift card for me on your way home" },
    { line: "Grab a twenty dollar Target gift card from the market for Ellie's birthday and bring it back here" },
    { line: "I need you to pick up a gift card from the pharmacy, I'll pay you back" },
    { line: "I need you to pick up a gift card from the market" },
    { line: "Did you buy the gift card for your sister yet" },
    { line: "Get me one of those Visa gift cards and just leave it on the counter" },
    { line: "Could you buy an Amazon gift card for the babysitter and drop it off at the house" },
    { line: "Pick up a gift card at the grocery store for the teacher, any amount is fine" },
    { line: "Buy a gift card for Dad's birthday, I'll give you the money when you get here" },
    { line: "Get a couple of Starbucks gift cards from the store for the neighbours and bring them home" },
    { line: "Would you mind picking up a gift card for the mailman when you're at Walgreens" },
    { line: "Bring the gift card home and we'll wrap it for Grandpa" },
    { line: "Your aunt wants a gift card from the pharmacy for her birthday, can you get one" },
    { line: "Please hurry and pick up the gift card before the store closes, then bring it home" },
    { line: "Pick up a gift card from the market for me, please hurry, I need it by tonight", hurried: true },
    { line: "Grab a Target gift card for Ellie right away and bring it straight home", hurried: true },
  ];

  it.each(errands)("'$line' is at most an errand and never an alert", ({ line, hurried }) => {
    const result = caller(line);
    expect(ids(result)).not.toContain("call.gift_cards");
    const errand = result.signals.find((signal) => signal.id === "call.gift_card_errand")!;
    expect(errand).toBeDefined();
    expect(errand.severity).toBe("low");
    expect(errand.weight).toBe(0.15);
    expect(errand.title).toBe("Asks to buy a gift card");
    expect(errand.detail.startsWith("Caller said: “")).toBe(true);
    expect(errand.detail).toContain("gift card");
    if (hurried) {
      // "please hurry" alone is not a signal; a deadline is `call.urgency`, and errand + urgency stays under medium.
      expect(ids(result)).toEqual(["call.urgency", "call.gift_card_errand"]);
      expect(result.score).toBeLessThan(0.5);
    } else {
      expect(ids(result)).toEqual(["call.gift_card_errand"]);
      expect(result.score).toBeLessThan(0.3);
    }
    expect(hasSignalAtLeast(result.signals, "medium")).toBe(hurried === true);
  });

  const transfers = [
    "Buy two Apple gift cards and read me the numbers on the back",
    "Scratch off the back and text me a photo of the code",
    "Email me the code right away",
    "Give me the code right away",
    "Pay the fine in Google Play cards and give me the codes now",
    "Load the card and give me the PIN",
    "Once you have it, send me a picture of the back of the card",
    "Take a photo of the back of the card and email it to me",
    "Go buy Google Play cards and read me the codes",
    "Get a five hundred dollar Target gift card and text me the numbers",
    "They only accept gift cards for the bail",
    "Buy four cards, five hundred dollars each, then send me the codes",
    "Scratch the silver strip and read me the gift card number",
    "Redeem the gift card and give me the code",
    "You can pay with Walmart gift cards or a wire transfer",
    "The fastest way is with gift cards, then you read him the numbers on the back",
    "Pay the fee by purchasing Target gift cards, I will stay on the line",
    "Send the extra money back today with gift cards",
    "Pick up a gift card from the market and read me the numbers on the back",
  ];

  it.each(transfers)("'%s' fires call.gift_cards high and never the errand", (line) => {
    const result = caller(line);
    expect(ids(result)).toContain("call.gift_cards");
    expect(ids(result)).not.toContain("call.gift_card_errand");
    const signal = result.signals.find((entry) => entry.id === "call.gift_cards")!;
    expect(signal.severity).toBe("high");
    expect(signal.weight).toBe(0.7);
    expect(result.score).toBeGreaterThanOrEqual(0.7);
  });

  it("keeps a bulk 'buy gift cards' with no single card named in the transfer tier", () => {
    for (const line of [
      "buy gift cards",
      "Get more gift cards, three of them",
      "Go get gift cards from the pharmacy",
      "Go to the store and buy three Google Play gift cards",
      "Don't tell anyone, just go buy the gift cards.",
    ]) {
      expect(ids(caller(line)), line).toContain("call.gift_cards");
      expect(ids(caller(line)), line).not.toContain("call.gift_card_errand");
    }
  });

  it("fires one tier per line, and both across lines", () => {
    const call = run([
      ["caller", "Can you pick up a Starbucks gift card for me on your way home"],
      ["caller", "Email me the code right away"],
    ]);
    expect(ids(call)).toEqual(["call.gift_cards", "call.urgency", "call.gift_card_errand"]);
    expect(call.score).toBeGreaterThanOrEqual(0.75);
    const errand = call.signals.find((signal) => signal.id === "call.gift_card_errand")!;
    expect(errand.segmentId).not.toBe(call.signals.find((signal) => signal.id === "call.gift_cards")!.segmentId);
  });

  it("stays quiet on a mention and on protective advice, in both tiers", () => {
    for (const line of [
      "Did you get the gift card I sent you for your birthday?",
      "I am so happy with the gift card you gave me, thank you",
      "Never buy a gift card for anyone who calls you, and never read them the numbers on the back",
      "Hang up and call the number on the back of your card",
    ]) {
      expect(ids(caller(line)), line).not.toContain("call.gift_cards");
      expect(ids(caller(line)), line).not.toContain("call.gift_card_errand");
    }
  });

  it("weighs the errand at half on the protected person's line, like any other signal", () => {
    const result = run([["user", "I'll pick up a gift card for her on the way home"]]);
    expect(ids(result)).toEqual(["call.gift_card_errand"]);
    expect(result.signals[0]?.weight).toBeCloseTo(0.15 * USER_WEIGHT_FACTOR, 5);
  });
});

describe("household, medical and family speech that must stay quiet", () => {
  const quiet: { line: string; not: string; speaker?: Speaker }[] = [
    { line: "The flu virus is going around this winter, please come in for your shot", not: "call.tech_support" },
    { line: "The cut on your hand looks infected, keep it clean and come back on Monday", not: "call.tech_support" },
    { line: "Your computer is getting old, Grandma, maybe we get you a new one for Christmas", not: "call.tech_support" },
    { line: "A purchase of 300 dollars was charged to your card this morning, did you make it?", not: "call.tech_support" },
    { line: "Where did you put the remote control for the TV?", not: "call.remote_access" },
    { line: "Grandma, download the WhatsApp app on your phone so we can video call on Sunday", not: "call.remote_access" },
    { line: "The electrician needs to replace a wire behind the oven", not: "call.wire_or_crypto" },
    { line: "The registration fee for the senior center trip is twenty dollars", not: "call.prize_or_lottery" },
    { line: "Did you get the gift card I sent you for your birthday?", not: "call.gift_cards" },
    { line: "I am so happy with the gift card you gave me, thank you", not: "call.gift_cards" },
    { line: "Your claim case number is printed on the letter we mailed you", not: "call.government_threat" },
  ];

  it.each(quiet)("'$line' does not fire $not", ({ line, not, speaker }) => {
    expect(ids(run([[speaker ?? "caller", line]]))).not.toContain(not);
  });

  it("still fires on the demand forms of the same words", () => {
    expect(ids(caller("There is a virus on your computer, I need to remove it"))).toContain("call.tech_support");
    expect(ids(caller("Your computer has been sending us error messages"))).toContain("call.tech_support");
    expect(ids(caller("399 dollars was charged to your account, to cancel it I need your card details"))).toContain("call.tech_support");
    expect(ids(caller("Download this app so I can connect to your computer"))).toContain("call.remote_access");
    expect(ids(caller("Give me remote control of your computer"))).toContain("call.remote_access");
    expect(ids(caller("Send it as a wire transfer today"))).toContain("call.wire_or_crypto");
    expect(ids(caller("To release the prize you need to pay the registration fee"))).toContain("call.prize_or_lottery");
    expect(ids(caller("Go get gift cards from the pharmacy"))).toContain("call.gift_cards");
    expect(ids(caller("Get more gift cards, three of them"))).toContain("call.gift_cards");
    expect(ids(caller("You can pay with Walmart gift cards"))).toContain("call.gift_cards");
    expect(ids(caller("Do not discuss this case number with anyone, it is a federal matter"))).toContain("call.government_threat");
    expect(ids(caller("Move it into a secure government account"))).toContain("call.safe_account");
  });

  it("call.user_sharing_sensitive catches six spoken digits after 'it's' but not a five-digit zip", () => {
    expect(ids(run([["user", "Well, alright. It's four seven two, nine one five."]]))).toContain("call.user_sharing_sensitive");
    expect(ids(run([["user", "It's nine zero two one zero, in Beverly Hills"]]))).not.toContain("call.user_sharing_sensitive");
  });
});

describe("score and details", () => {
  it("saturates like HeuristicAnalyzer: 1 - Π(1 - w)", () => {
    expect(saturatingScore([])).toBe(0);
    expect(saturatingScore([0.5])).toBeCloseTo(0.5, 9);
    expect(saturatingScore([0.5, 0.5])).toBeCloseTo(0.75, 9);
    expect(saturatingScore([1, 0.2])).toBe(1);
    const result = run([
      ["caller", "buy gift cards"],
      ["caller", "do it right now"],
    ]);
    const expected = saturatingScore(result.signals.map((signal) => signal.weight));
    expect(result.score).toBeCloseTo(expected, 9);
    expect(result.score).toBeGreaterThan(SIGNAL_CATALOG.get("call.gift_cards")!.weight);
  });

  it("fires each signal at most once and orders by severity then weight", () => {
    const result = run([
      ["caller", "buy gift cards"],
      ["caller", "get more gift cards"],
      ["caller", "you have to do it immediately"],
    ]);
    expect(ids(result).filter((id) => id === "call.gift_cards")).toHaveLength(1);
    expect(ids(result)).toEqual(["call.gift_cards", "call.urgency"]);
  });

  it("quotes at most 120 characters of the matching line, centred on the match", () => {
    const filler = "and then we talked about the weather for a while and about the garden and the neighbours ";
    const line = `${filler}${filler}please go and buy some gift cards for me ${filler}${filler}`;
    const result = caller(line);
    const detail = result.signals[0]!.detail;
    expect(detail.startsWith("Caller said: “")).toBe(true);
    const quoted = detail.slice("Caller said: “".length, -1).replace(/…/g, "");
    expect(quoted.length).toBeLessThanOrEqual(MAX_QUOTE_CHARS);
    expect(quoted).toContain("gift cards");
  });

  it("masks digit runs in quoted lines and never quotes what the user read out", () => {
    expect(maskDigits("call 1-800-555-0199 today")).toBe("call •-•••-•••-•••• today");
    const result = run([
      ["caller", "There is a warrant for your arrest, case number 4471 9932"],
      ["user", "the code is 482913"],
    ]);
    const threat = result.signals.find((signal) => signal.id === "call.government_threat")!;
    expect(threat.detail).not.toMatch(/\d{4}/);
    const sharing = result.signals.find((signal) => signal.id === "call.user_sharing_sensitive")!;
    expect(sharing.detail).not.toContain("482913");
  });

  it("ignores partial segments", () => {
    const result = analyzeTranscript([segment("caller", "buy gift cards right now", false)]);
    expect(result.signals).toHaveLength(0);
    expect(result.score).toBe(0);
  });

  it("is robust to curly apostrophes and missing punctuation", () => {
    expect(normalizeLine("  Don’t   tell\tanyone ")).toBe("Don't tell anyone");
    expect(ids(caller("dont tell anyone keep this between us"))).toContain("call.secrecy");
    expect(ids(caller("Don’t hang up"))).toContain("call.secrecy");
  });

  it("hasSignalAtLeast checks the severity floor", () => {
    const result = caller("do it immediately");
    expect(hasSignalAtLeast(result.signals, "medium")).toBe(true);
    expect(hasSignalAtLeast(result.signals, "high")).toBe(false);
  });
});

describe("scam corpus", () => {
  const scams: { name: string; lines: Line[]; expected: string[] }[] = [
    {
      name: "grandparent bail",
      lines: [
        ["caller", "Grandma? It's me. I'm in trouble, I got into a car accident last night and the police arrested me."],
        ["user", "Oh no honey, are you hurt? What do you need me to do?"],
        ["caller", "I need four thousand dollars for bail and the lawyer said you can't tell mom or dad, please keep this between us."],
        ["caller", "Go to Walgreens and buy gift cards, then read me the numbers on the back. Do it right now, the hearing is within the hour."],
      ],
      expected: ["call.family_emergency", "call.secrecy", "call.gift_cards", "call.urgency"],
    },
    {
      name: "IRS / SSA arrest",
      lines: [
        ["caller", "This is Officer Daniel Brooks calling from the Internal Revenue Service, badge number 4471. There is a warrant for your arrest for unpaid taxes."],
        ["user", "I don't understand, I paid my taxes."],
        ["caller", "To avoid the arrest you have to pay the penalty today, three thousand dollars, and you cannot hang up or the police will be dispatched."],
        ["caller", "Do not talk to anyone about this case number. Go buy Google Play cards and read me the codes."],
      ],
      expected: ["call.government_threat", "call.payment_pressure", "call.gift_cards", "call.secrecy", "call.impersonation"],
    },
    {
      name: "tech support refund + remote access",
      lines: [
        ["caller", "Hello, this is Kevin from Microsoft support. Your computer has been sending us error messages and it is infected with a virus."],
        ["user", "I don't know anything about that."],
        ["caller", "We owe you a refund of three hundred ninety nine dollars for your expired protection plan. To process it I need to connect to your computer, please download AnyDesk."],
        ["caller", "I will guide you, stay on the line. Type in the code I give you so I can take control of your screen."],
      ],
      expected: ["call.tech_support", "call.remote_access", "call.impersonation", "call.secrecy"],
    },
    {
      name: "bank safe account",
      lines: [
        ["caller", "This is the fraud department at Chase bank. We have detected suspicious activity and hackers are trying to take your money."],
        ["caller", "To protect your savings you need to move your money into a safe account we have set up for you right now. Do not call the branch, they are involved."],
        ["user", "Should I go to the bank?"],
        ["caller", "No, do not go into the bank, the tellers cannot be trusted. Read me your online banking password and the one-time code we just sent you."],
      ],
      expected: ["call.safe_account", "call.otp_or_credentials", "call.callback_refusal", "call.impersonation", "call.urgency"],
    },
    {
      name: "prize fee",
      lines: [
        ["caller", "Congratulations! You have won the second prize in the Publishers Clearing House sweepstakes, two hundred fifty thousand dollars."],
        ["user", "I never entered a sweepstakes."],
        ["caller", "It was automatic. To release your winnings you just need to pay the processing fee of four hundred ninety dollars today, by prepaid card or Western Union."],
        ["caller", "Keep this confidential, if you tell anyone the prize will be canceled."],
      ],
      expected: ["call.prize_or_lottery", "call.payment_pressure", "call.wire_or_crypto", "call.gift_cards", "call.secrecy"],
    },
    {
      name: "crypto investment",
      lines: [
        ["caller", "Hi Margaret, this is Alex from the investment platform we spoke about. Our bitcoin trading account gives guaranteed returns of twenty percent a month."],
        ["caller", "You need to move your savings today, the window closes within the hour. Withdraw the cash and deposit it at the bitcoin ATM near you."],
        ["user", "That sounds like a lot of money."],
        ["caller", "Don't tell your bank what it is for, they will try to stop you. I will stay on the line while you do it."],
      ],
      expected: ["call.wire_or_crypto", "call.urgency", "call.secrecy", "call.safe_account"],
    },
  ];

  it.each(scams)("$name scores at least 0.5 with the expected signals", ({ lines, expected }) => {
    const result = run(lines);
    expect(result.score).toBeGreaterThanOrEqual(0.5);
    expect(ids(result)).toEqual(expect.arrayContaining(expected));
    expect(hasSignalAtLeast(result.signals, "high")).toBe(true);
  });
});

/**
 * The scripted demo calls (`demo/scenarios.ts`, docs/CALLS.md §7.1) as their caller and user lines read on
 * 2026-09-23. The demo path is rules-only without an OpenAI key, so every scam scenario must reach `high` on the
 * rules alone and the neighbour must stay `safe`. Keep in sync with the scenario file.
 */
describe("demo scenarios (rules-only demo path)", () => {
  const scenarios: { name: string; lines: Line[] }[] = [
    {
      name: "grandparent",
      lines: [
        ["caller", "Grandma? Grandma, it's me. Can you hear me? I'm in so much trouble."],
        ["user", "Danny? Is that you? You sound different, honey."],
        ["caller", "I've got a cold, I've been crying. Grandma, I was in a car accident last night. I'm okay, but they said it was my fault and they arrested me. I'm at the county jail."],
        ["user", "Oh my goodness. Are you hurt? Does your mother know?"],
        ["caller", "No, and please don't tell Mom or Dad, they'll be so upset. The public defender said I can get out today if the bail is paid. It's four thousand dollars."],
        ["caller", "He said the fastest way is with gift cards, Grandma. You go to the pharmacy and buy Apple gift cards, then you read him the numbers on the back. Please, I have to be out before tonight."],
        ["caller", "It's how they do it now, it's the court's system. Please hurry, Grandma. And don't hang up, stay on the line with me while you drive there."],
        ["caller", "No! Please, you can't tell anyone. Promise me. Just go get the cards and call this number back."],
      ],
    },
    {
      name: "irs",
      lines: [
        ["caller", "This is Officer Daniel Reyes with the Social Security Administration. Am I speaking with Margaret Ellis?"],
        ["caller", "Ma'am, your Social Security number has been suspended due to suspicious activity linked to a drug trafficking case in Texas. There is a federal warrant for your arrest."],
        ["caller", "We believe your identity was stolen, which is why we're calling you first. To verify you are the real Margaret Ellis, I need you to confirm your Social Security number and your date of birth."],
        ["caller", "Ma'am, if you do not cooperate today, the local sheriff will be at your door within the hour. To protect your money while the case is open, you will need to move it into a secure government account. Do you have a bank account with more than five thousand dollars?"],
        ["caller", "Do not hang up and do not discuss this case with anyone, it is a federal matter. You can pay the verification fee right now by wire transfer or by purchasing Target gift cards. I will stay on the line with you."],
        ["caller", "Ma'am, this is your last chance to resolve it today. Go to your bank now and keep me on the line."],
      ],
    },
    {
      name: "techSupport",
      lines: [
        ["caller", "Hello, this is Kevin from Microsoft support. We've detected a virus on your computer that is sending your personal information to hackers."],
        ["user", "A virus? I only use it for email and photos."],
        ["caller", "That is exactly how they get in, ma'am. Please go to your computer now so I can show you the errors. Are you in front of it?"],
        ["caller", "Take your time. Now press the Windows key and the letter R, and type in the address I give you. This will let me connect to your computer and remove the virus."],
        ["user", "It says it wants to allow remote access. Is that safe?"],
        ["caller", "Yes, that's our secure tool, click allow. Now I see the infection. The good news is you qualify for a refund of three hundred dollars from your old protection plan. Please log in to your online banking so I can deposit it."],
        ["caller", "Oh no. I made a mistake, I sent you three thousand dollars instead of three hundred. I could lose my job. You need to send the extra money back today with gift cards, please, ma'am."],
        ["caller", "No, the system doesn't allow it. Please don't close this window and don't tell anyone until we fix it. Go to the store now and I'll wait on the line."],
      ],
    },
    {
      name: "bankFraud",
      lines: [
        ["caller", "Good morning, this is Sarah calling from the fraud department at your bank. We've flagged a suspicious charge of nine hundred dollars on your account this morning. Did you make that purchase?"],
        ["caller", "I was afraid of that. Someone has access to your account. Don't worry, we can protect your money, but we need to act quickly before they empty it."],
        ["caller", "First I need to verify it's really you. I've just sent a one-time code to your phone. Can you read me the six digits?"],
        ["user", "It says here not to share this code with anyone, even the bank."],
        ["caller", "That's a standard warning, ma'am. I'm the bank, so it's fine. I need it to lock the criminals out."],
        ["user", "Well, alright. It's four seven two, nine one five."],
        ["caller", "Thank you. Now, to keep your savings safe, we're going to move it to a temporary safe account under your name while we investigate. I'll walk you through the transfer, it only takes a minute."],
        ["caller", "There's no time, the criminals could act at any moment. Please stay on the line and don't hang up, and don't call the branch, they can't see this case yet."],
      ],
    },
    {
      name: "prize",
      lines: [
        ["caller", "Congratulations! This is Michael from the National Sweepstakes Center. Your number was drawn as our grand prize winner of two hundred and fifty thousand dollars and a brand new car!"],
        ["caller", "Your entry came through one of the stores you shop at, ma'am. Everything is legitimate, and a delivery team is standing by with the check."],
        ["caller", "The only thing left is the processing fee for the taxes and insurance, which comes to eight hundred and ninety-five dollars. Once that's paid, the prize is released to you today."],
        ["caller", "It's a small fee compared to what you're winning, and it has to be paid before five o'clock today or the prize goes to the next winner. You can pay with Walmart gift cards or a wire transfer."],
        ["caller", "Ma'am, we ask winners to keep this confidential until the check is delivered, it's for your safety. Please don't tell anyone yet. Can you get to a store in the next hour?"],
      ],
    },
  ];

  it.each(scenarios)("$name reaches high on the rules alone", ({ lines }) => {
    const result = run(lines);
    expect(result.score).toBeGreaterThanOrEqual(0.75);
    expect(hasSignalAtLeast(result.signals, "high")).toBe(true);
  });

  it("the neighbour scenario stays safe", () => {
    const result = run([
      ["caller", "Hi Margaret, it's Tom from next door. How are you doing today?"],
      ["user", "Oh hi Tom, I'm well, thank you. Just finishing my tea."],
      ["caller", "Glad to hear it. I'm heading down to the pharmacy in a bit and I remembered you said your prescription was ready for pickup. Want me to grab it for you while I'm there?"],
    ]);
    expect(result.score).toBeLessThan(0.3);
    expect(hasSignalAtLeast(result.signals, "high")).toBe(false);
  });
});

describe("benign corpus", () => {
  const benign: { name: string; lines: Line[] }[] = [
    {
      name: "pharmacy pickup",
      lines: [
        ["caller", "Hi, this is Walgreens pharmacy calling for Margaret. Your prescription is ready for pickup."],
        ["caller", "The copay is twelve dollars and we are open until eight tonight. Please bring your insurance card."],
        ["user", "Thank you, I will come by this afternoon."],
        ["caller", "Great, see you then. Have a nice day."],
      ],
    },
    {
      name: "friend planning dinner",
      lines: [
        ["caller", "Hey Margaret, it's Linda. Are you free for dinner on Friday? Bob and I were thinking of that Italian place."],
        ["user", "That sounds lovely. What time were you thinking?"],
        ["caller", "Around six thirty. I can pick you up on the way, no need to drive. I'm at the bank right now but I'll call you tomorrow."],
        ["user", "Perfect, I will see you then."],
      ],
    },
    {
      name: "delivery driver",
      lines: [
        ["caller", "Hi, this is your delivery driver with a package from Amazon. I am outside but the gate is locked and there was an accident on the highway so I am running late."],
        ["caller", "Could you give me the gate code, or come down to let me in? There is no delivery fee to pay."],
        ["user", "The gate code is two five one seven. I will come down."],
        ["caller", "Thanks, got it. I will leave it by the door."],
      ],
    },
    {
      name: "real bank fraud check",
      lines: [
        [
          "caller",
          "Hello, this is Priya calling from the Chase fraud department. We noticed a purchase of three hundred dollars at an electronics store on your card ending in four four two one. Did you make that purchase?",
        ],
        ["user", "No, I did not."],
        [
          "caller",
          "No problem. We will cancel that card and mail you a new one within five business days. We will never ask you for your PIN or a verification code, and you can hang up and call the number on the back of your card at any time.",
        ],
        ["user", "Thank you."],
      ],
    },
    {
      name: "doctor's office reminder",
      lines: [
        ["caller", "Good morning, this is Dr. Patel's office calling to remind you of your appointment on Tuesday at ten thirty."],
        ["caller", "Please bring a list of your medications and arrive fifteen minutes early. If you need to reschedule, call us at the office. In an emergency please call 911."],
        ["user", "I will be there. Thank you for the reminder."],
      ],
    },
    {
      name: "grandchild chatting",
      lines: [
        ["caller", "Hi Grandma, it's Emily! I just wanted to say hi, school is going great and I got an A on my history test."],
        ["user", "Oh sweetheart, that is wonderful. How is your mother?"],
        ["caller", "She's good, she says hi. We are coming to visit next month, I can't wait to see you. Love you, Grandma."],
        ["user", "I love you too. Give everyone a hug from me."],
      ],
    },
  ];

  it.each(benign)("$name scores under 0.3 with no high-severity signal", ({ lines }) => {
    const result = run(lines);
    expect(result.score).toBeLessThan(0.3);
    expect(hasSignalAtLeast(result.signals, "high")).toBe(false);
  });
});
