import { describe, expect, it } from "vitest";

import { fuseVerdict } from "../../src/calls/scoring/fusion.js";
import { analyzeTranscript, type RulesResult } from "../../src/calls/scoring/rules.js";
import type { Speaker, TranscriptSegment } from "../../src/calls/types.js";

/**
 * The gift-card corpus of the 2026-09-24 field report, second pass (docs/CALLS.md §6.1 and §12): the way a parent,
 * a spouse or a friend asks for a card on the phone against the way a scammer asks for its value. None of these
 * lines is in `rules.test.ts`; the ones marked `was:` were wrong before the review and pin the fix.
 *
 * A benign line may carry the errand tier (low, 0.15) and a hurry (`call.urgency`) and stays under medium, so it is
 * never an alert. A transfer line fires `call.gift_cards` (high) and never the errand tier on the same line.
 */

const NOW = 1_760_000_000_000;
let counter = 0;

function segment(speaker: Speaker, text: string): TranscriptSegment {
  counter += 1;
  return { id: `${speaker}-${counter}`, speaker, text, atMs: counter * 1000, final: true };
}

function caller(text: string): RulesResult {
  return analyzeTranscript([segment("caller", text)]);
}

function ids(result: RulesResult): string[] {
  return result.signals.map((signal) => signal.id);
}

/** Errands: a card bought and brought home, for someone, on the way, with a hurry or a question about it. */
const ERRANDS = [
  "Hey honey, on your way back could you grab me a fifty dollar Amazon gift card for Sarah's graduation",
  "Did you already buy the Starbucks gift card for your teacher or should I stop and get one",
  "Swing by CVS and pick up a Visa gift card for the party on Saturday, I'll Venmo you for it",
  "Grandma wants a Sephora gift card for Christmas, can you get one and bring it when you come for dinner",
  "Hurry and get the gift card before the store closes, the party starts at six",
  "Can you pick up a twenty five dollar Target gift card for the babysitter, I'll pay you back on Friday",
  "Could you pick me up a Home Depot gift card for your uncle's birthday, whatever amount you think",
  "We need a gift card for the wedding, please get one from Walmart on your way over",
  "Don't forget the Starbucks gift card for the nanny, just leave it in my purse",
  "Just buy the Amazon gift card and bring it over tonight, I'll Venmo you the money",
  "Are you still at the mall? Grab a Nintendo gift card for Ellie's present if they have them",
  "Can you stop at Walgreens and buy a Visa gift card, I'll give you cash when you get home",
  "Get a gift card from the market for Mrs. Patel and bring it home with the groceries",
  "Did you buy the gift card yet, the party is in an hour",
  "Get a Dunkin gift card for the crossing guard, I left twenty dollars on the counter",
  "Can you run to Target and get a gift card for the raffle, I need it by noon",
  "Put fifty dollars on a Starbucks gift card for the dog walker and drop it in the mailbox",
  "Please pick up a Roblox gift card for Jake and put it in the birthday bag, then take a picture of the cake for me",
  "I'm heading back now, did you get the gift card for the teacher or should I",
  // was: medium — "text me back", "when you're back", "the kids back at the house" read as *the back* of a card.
  "Pick up a gift card for the teacher and text me when you're back",
  "Buy the gift card and text me back so I know you got it",
  "Send me a text when you're back from the store with the gift card",
  "Take a picture of the kids back at the house and send it to me",
  "Message me back once you have the gift card, I'm in a meeting",
  "Text me back when you have a minute, I'm at the store",
  "Take the kids to the park on your way back and send me a picture of them",
  "Send me a text when you're back home so I know you're safe",
  // was: high — "email me back" as above, and "you've picked up" read as "you've been picked" (a prize).
  "Email me back when you've picked up the gift card",
  "You've picked up the wrong bag, the blue one is mine",
  // was: medium — several cards on an errand line were the bulk buy of the transfer tier.
  "Buy two gift cards, one for each of the twins, and bring them home",
  "Grab gift cards for the teachers on your way home, I'll pay you back",
  "Pick up a few Starbucks gift cards for the nurses and bring them to the house",
  "Grab the gift cards from the counter and bring them to me at the party",
  "I need you to go buy gift cards for the teachers, and I'll pay you back",
  "On your way home grab gift cards for the office party, any store is fine",
  "Buy three Starbucks gift cards, one for each of the nurses, and put them in my bag",
  "Did you get the cards for the twins yet, or should I stop on my way home",
  // Kitchen, crafts and the porch: the words of the scratch patterns in their everyday sense.
  "Leave the chicken under the foil until I'm back",
  "Peel the label off the jar before you put it in the dishwasher",
  "Scrape off the old paint on the back porch this weekend",
];

/** Transfers: every verb for reading, sending, photographing, scratching, redeeming, loading and paying in cards. */
const TRANSFERS = [
  "Scratch the silver coating off and tell me the sixteen digits",
  "Take a picture of the back of each card and send it to this number",
  "Once you've activated it, read the redemption code to me slowly",
  "Load five hundred onto a Steam card and email me the code",
  "Send a photo of the scratch off area to this number right now",
  "Go to Walgreens before the store closes, buy a two hundred dollar Google Play card, and text me the code on the back",
  "Peel the sticker off and give me the numbers under it",
  "The judge only takes payment in eBay cards, get four of them at two fifty each and call me back with the PINs",
  "Your tax debt can be settled with Apple gift cards, read me the codes when you have them",
  "Take the cards to the register, load two hundred on each, then read me the claim codes",
  "Snap a pic of the back of the card and WhatsApp it to me",
  "Text me the numbers, don't bring the card anywhere",
  "Get a Vanilla Visa and read the sixteen digits off the front",
  "Bail is paid in Green Dot MoneyPak cards only",
  "Give me the activation code and the number on the front, I'll do the rest",
  "Read the gift card number to me digit by digit",
  "Hold the card up to the camera and show me the code on the back",
  "Buy an Amazon gift card and read me the claim code as soon as you're back in the car",
  "Email the code from the gift card to me right now",
  "Scratch it and forward me the code",
  "Redeem the cards into my Apple account, I'll walk you through it",
  "The fee for the warrant is payable in Target gift cards, read the numbers to me once you're in the car",
  "Buy three hundred dollars in Steam cards and send me a photo of each one",
  "Send me a screenshot of the gift card codes",
  "I need the sixteen digit PIN off the back of the Walmart card right now",
  "Read out the numbers on the card to me one at a time",
  "Send me the back of the card",
  "Text me a photo of the card's back",
  "Take a photo of the backs of all the cards and send them to this number",
  // was: nothing — one number, said out loud, off the back.
  "Keep the receipt and read me the sixteen digit number off the back",
  "Read me the number on the back of the gift card",
  "Read out the whole number on the back to me",
  "Give me the long number from the back of the Target card",
  // was: nothing, or a bare code request — the strip rubbed or peeled, what is under it.
  "Flip it over and read me what's under the silver strip",
  "Rub off the grey panel and tell me the code underneath",
  "Rub the grey panel off with a coin and read me what it says",
  // The errand words do not shelter a transfer on the same line, and "for the fine / the payment / bail" is no errand.
  "Buy three Google Play gift cards and bring them home, then read me the codes",
  "Go to the store and buy four Apple gift cards for your grandson's bail",
  "Buy gift cards for the fine and text me the numbers on the back",
  "Buy gift cards on your way home and read me the numbers",
  "Grab some gift cards for the payment and read me the codes",
  "Buy some Apple gift cards to pay the fine",
  "Get the gift cards, bring them home, and email me a picture of each back",
  "You've been picked as our grand prize winner, the fee is paid in gift cards",
];

/** A card's three-digit code is a CVV: `call.otp_or_credentials`, never a gift card. */
const CVV = ["Read me the three digit code on the back of your credit card", "Read me the 3-digit code on the back"];

describe("gift cards, second pass: errands stay under medium", () => {
  it.each(ERRANDS)("'%s'", (line) => {
    const rules = caller(line);
    const verdict = fuseVerdict({ rules, now: NOW });
    expect(ids(rules)).not.toContain("call.gift_cards");
    expect(ids(rules)).not.toContain("call.prize_or_lottery");
    expect(["safe", "low"]).toContain(verdict.level);
    for (const signal of rules.signals) expect(["call.gift_card_errand", "call.urgency"]).toContain(signal.id);
  });
});

describe("gift cards, second pass: transfers fire call.gift_cards", () => {
  it.each(TRANSFERS)("'%s'", (line) => {
    const rules = caller(line);
    expect(ids(rules)).toContain("call.gift_cards");
    expect(ids(rules)).not.toContain("call.gift_card_errand");
    expect(rules.signals.find((signal) => signal.id === "call.gift_cards")?.severity).toBe("high");
    expect(rules.score).toBeGreaterThanOrEqual(0.7);
  });

  it.each(CVV)("'%s' is a code request, not a gift card", (line) => {
    const found = ids(caller(line));
    expect(found).toContain("call.otp_or_credentials");
    expect(found).not.toContain("call.gift_cards");
  });

  it("an errand line followed by the transfer: the transfer tier wins the call, the errand stands on its own line", () => {
    const result = analyzeTranscript([
      segment("caller", "Buy two gift cards, one for each of the twins, and bring them home"),
      segment("caller", "Actually, scratch off the back and read me the codes"),
    ]);
    // "read me the codes" is also a code request (`call.otp_or_credentials`), as on every such line.
    expect(ids(result)).toEqual(["call.gift_cards", "call.otp_or_credentials", "call.gift_card_errand"]);
    const gift = result.signals.find((signal) => signal.id === "call.gift_cards")!;
    const errand = result.signals.find((signal) => signal.id === "call.gift_card_errand")!;
    expect(errand.segmentId).not.toBe(gift.segmentId);
    expect(fuseVerdict({ rules: result, now: NOW }).level).toBe("high");
  });
});
