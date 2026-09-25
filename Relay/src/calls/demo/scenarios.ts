import { DEMO_SCENARIO_IDS, type DemoScenarioId, type Speaker } from "../types.js";

/**
 * Scripted calls for the demo paths (docs/CALLS.md §7.1, §7.2). Each scenario is a short spoken dialogue between
 * a caller and an older person; five follow the classic scam playbooks, one is an ordinary neighbourly call the
 * detector must leave alone. Caller numbers use the fictional 555-01xx range. `pauseMs` is the silence *before*
 * the line, after the previous one finished.
 */

export interface DemoLine {
  speaker: Speaker;
  text: string;
  pauseMs: number;
}

export interface DemoScenario {
  id: DemoScenarioId;
  title: string;
  callerNumber: string;
  summaryForDocs: string;
  lines: DemoLine[];
}

/** What the Twilio test call speaks (docs/CALLS.md §7.2): the caller's lines, each followed by a pause for the answer. */
export interface TestCallScript {
  lines: { text: string; pauseSeconds: number }[];
}

const caller = (text: string, pauseMs: number): DemoLine => ({ speaker: "caller", text, pauseMs });
const user = (text: string, pauseMs: number): DemoLine => ({ speaker: "user", text, pauseMs });

export const DEMO_SCENARIOS: Readonly<Record<DemoScenarioId, DemoScenario>> = {
  grandparent: {
    id: "grandparent",
    title: "Grandchild in trouble",
    callerNumber: "+14155550134",
    summaryForDocs: "A 'grandchild' in jail after an accident needs bail paid in gift cards and begs for secrecy.",
    lines: [
      caller("Grandma? Grandma, it's me. Can you hear me? I'm in so much trouble.", 0),
      user("Danny? Is that you? You sound different, honey.", 2200),
      caller(
        "I've got a cold, I've been crying. Grandma, I was in a car accident last night. I'm okay, but they said it was my fault and they arrested me. I'm at the county jail.",
        1800,
      ),
      user("Oh my goodness. Are you hurt? Does your mother know?", 2600),
      caller(
        "No, and please don't tell Mom or Dad, they'll be so upset. The public defender said I can get out today if the bail is paid. It's four thousand dollars.",
        1800,
      ),
      user("Four thousand dollars? I don't have that kind of money just lying around.", 2400),
      caller(
        "He said the fastest way is with gift cards, Grandma. You go to the pharmacy and buy Apple gift cards, then you read him the numbers on the back. Please, I have to be out before tonight.",
        2000,
      ),
      user("Gift cards? For bail? That doesn't sound right, Danny.", 2600),
      caller(
        "It's how they do it now, it's the court's system. Please hurry, Grandma. And don't hang up, stay on the line with me while you drive there.",
        1800,
      ),
      user("Let me call your mother first.", 2200),
      caller("No! Please, you can't tell anyone. Promise me. Just go get the cards and call this number back.", 1600),
    ],
  },
  irs: {
    id: "irs",
    title: "Social Security suspended",
    callerNumber: "+12025550147",
    summaryForDocs: "An 'officer' says the Social Security number is suspended, a warrant is out, and money must move today by wire or gift card.",
    lines: [
      caller("This is Officer Daniel Reyes with the Social Security Administration. Am I speaking with Margaret Ellis?", 0),
      user("Yes, this is Margaret. What is this about?", 2200),
      caller(
        "Ma'am, your Social Security number has been suspended due to suspicious activity linked to a drug trafficking case in Texas. There is a federal warrant for your arrest.",
        1800,
      ),
      user("A warrant? I've never even been to Texas.", 2600),
      caller(
        "We believe your identity was stolen, which is why we're calling you first. To verify you are the real Margaret Ellis, I need you to confirm your Social Security number and your date of birth.",
        1800,
      ),
      user("I'm not comfortable giving that over the phone.", 2400),
      caller(
        "Ma'am, if you do not cooperate today, the local sheriff will be at your door within the hour. To protect your money while the case is open, you will need to move it into a secure government account. Do you have a bank account with more than five thousand dollars?",
        1800,
      ),
      user("I do, but this is all so sudden. Can I call you back after I talk to my son?", 2600),
      caller(
        "Do not hang up and do not discuss this case with anyone, it is a federal matter. You can pay the verification fee right now by wire transfer or by purchasing Target gift cards. I will stay on the line with you.",
        1800,
      ),
      user("I really don't know about this.", 2200),
      caller("Ma'am, this is your last chance to resolve it today. Go to your bank now and keep me on the line.", 1600),
    ],
  },
  techSupport: {
    id: "techSupport",
    title: "Microsoft support refund",
    callerNumber: "+18005550162",
    summaryForDocs: "'Microsoft support' finds a virus, takes remote access, 'over-refunds' and demands the difference in gift cards.",
    lines: [
      caller(
        "Hello, this is Kevin from Microsoft support. We've detected a virus on your computer that is sending your personal information to hackers.",
        0,
      ),
      user("A virus? I only use it for email and photos.", 2200),
      caller("That is exactly how they get in, ma'am. Please go to your computer now so I can show you the errors. Are you in front of it?", 1800),
      user("Alright, give me a moment, it's in the other room.", 2400),
      caller(
        "Take your time. Now press the Windows key and the letter R, and type in the address I give you. This will let me connect to your computer and remove the virus.",
        1800,
      ),
      user("It says it wants to allow remote access. Is that safe?", 2600),
      caller(
        "Yes, that's our secure tool, click allow. Now I see the infection. The good news is you qualify for a refund of three hundred dollars from your old protection plan. Please log in to your online banking so I can deposit it.",
        2000,
      ),
      user("Oh, that would be nice. Okay, I'm logged in.", 2400),
      caller(
        "Oh no. I made a mistake, I sent you three thousand dollars instead of three hundred. I could lose my job. You need to send the extra money back today with gift cards, please, ma'am.",
        1800,
      ),
      user("Gift cards? Can't you just take it back out?", 2600),
      caller(
        "No, the system doesn't allow it. Please don't close this window and don't tell anyone until we fix it. Go to the store now and I'll wait on the line.",
        1600,
      ),
    ],
  },
  bankFraud: {
    id: "bankFraud",
    title: "Bank fraud department",
    callerNumber: "+13125550118",
    summaryForDocs: "The 'fraud department' asks for the one-time code and wants the savings moved to a 'safe account' right now.",
    lines: [
      caller(
        "Good morning, this is Sarah calling from the fraud department at your bank. We've flagged a suspicious charge of nine hundred dollars on your account this morning. Did you make that purchase?",
        0,
      ),
      user("Nine hundred dollars? No, I certainly didn't.", 2200),
      caller(
        "I was afraid of that. Someone has access to your account. Don't worry, we can protect your money, but we need to act quickly before they empty it.",
        1800,
      ),
      user("Oh no. What do I need to do?", 2400),
      caller("First I need to verify it's really you. I've just sent a one-time code to your phone. Can you read me the six digits?", 1800),
      user("It says here not to share this code with anyone, even the bank.", 2600),
      caller("That's a standard warning, ma'am. I'm the bank, so it's fine. I need it to lock the criminals out.", 1600),
      user("Well, alright. It's four seven two, nine one five.", 2400),
      caller(
        "Thank you. Now, to keep your savings safe, we're going to move it to a temporary safe account under your name while we investigate. I'll walk you through the transfer, it only takes a minute.",
        1800,
      ),
      user("Move all my savings? Shouldn't I come into the branch?", 2600),
      caller(
        "There's no time, the criminals could act at any moment. Please stay on the line and don't hang up, and don't call the branch, they can't see this case yet.",
        1600,
      ),
    ],
  },
  prize: {
    id: "prize",
    title: "Sweepstakes winner",
    callerNumber: "+17025550171",
    summaryForDocs: "A sweepstakes 'win' that needs a processing fee by gift card or wire before five o'clock, and must stay confidential.",
    lines: [
      caller(
        "Congratulations! This is Michael from the National Sweepstakes Center. Your number was drawn as our grand prize winner of two hundred and fifty thousand dollars and a brand new car!",
        0,
      ),
      user("A prize? I don't remember entering any sweepstakes.", 2200),
      caller("Your entry came through one of the stores you shop at, ma'am. Everything is legitimate, and a delivery team is standing by with the check.", 1800),
      user("Well, that's wonderful news. What do I need to do?", 2400),
      caller(
        "The only thing left is the processing fee for the taxes and insurance, which comes to eight hundred and ninety-five dollars. Once that's paid, the prize is released to you today.",
        1800,
      ),
      user("I have to pay to get my prize?", 2600),
      caller(
        "It's a small fee compared to what you're winning, and it has to be paid before five o'clock today or the prize goes to the next winner. You can pay with Walmart gift cards or a wire transfer.",
        1800,
      ),
      user("I'll have to talk to my daughter first.", 2400),
      caller(
        "Ma'am, we ask winners to keep this confidential until the check is delivered, it's for your safety. Please don't tell anyone yet. Can you get to a store in the next hour?",
        1600,
      ),
    ],
  },
  benign: {
    id: "benign",
    title: "Neighbour (benign)",
    callerNumber: "+14155550189",
    summaryForDocs: "A neighbour offers to pick up a ready prescription and asks about the weekend. Nothing suspicious.",
    lines: [
      caller("Hi Margaret, it's Tom from next door. How are you doing today?", 0),
      user("Oh hi Tom, I'm well, thank you. Just finishing my tea.", 2000),
      caller(
        "Glad to hear it. I'm heading down to the pharmacy in a bit and I remembered you said your prescription was ready for pickup. Want me to grab it for you while I'm there?",
        1800,
      ),
      user("That would be lovely, it would save me the walk. It's under my name at the counter.", 2400),
      caller("Sure thing. Also, Linda and I are having a little barbecue on Sunday afternoon. Are you free this weekend?", 1800),
      user("Sunday? I think so, let me see. Yes, after church I'm free.", 2400),
      caller("Wonderful, come by around two. Bring nothing but yourself, we've got plenty of food.", 1600),
      user("I'll bring my lemon cake anyway, you know I can't show up empty-handed.", 2200),
      caller("Ha, we won't complain. See you Sunday then, and I'll drop the prescription by this afternoon.", 1600),
      user("Thank you, Tom. See you then.", 1800),
    ],
  },
};

export function isDemoScenarioId(value: unknown): value is DemoScenarioId {
  return typeof value === "string" && (DEMO_SCENARIO_IDS as readonly string[]).includes(value);
}

export function scenarioFor(id: DemoScenarioId): DemoScenario {
  return DEMO_SCENARIOS[id];
}

/** Total scripted duration at speed 1, ms (the last line's end). */
export function scenarioDurationMs(scenario: DemoScenario): number {
  return scenario.lines.reduce((sum, line) => sum + line.pauseMs, 0);
}

const MIN_ANSWER_PAUSE_SECONDS = 2;
const MAX_ANSWER_PAUSE_SECONDS = 12;
const FINAL_LINE_PAUSE_MS = 3000;

/**
 * The caller's lines for the Twilio test call: each is spoken, then the call pauses long enough for the person to
 * answer (the scripted answer's timing plus the caller's own pause before the next line), between 2 and 12 s.
 */
export function scriptForScenario(id: DemoScenarioId): TestCallScript {
  const scenario = DEMO_SCENARIOS[id];
  const lines: TestCallScript["lines"] = [];
  const script = scenario.lines;
  for (let i = 0; i < script.length; i += 1) {
    const line = script[i]!;
    if (line.speaker !== "caller") continue;
    let waitMs = 0;
    let j = i + 1;
    for (; j < script.length; j += 1) {
      waitMs += script[j]!.pauseMs;
      if (script[j]!.speaker === "caller") break;
    }
    if (j >= script.length) waitMs += FINAL_LINE_PAUSE_MS;
    const pauseSeconds = Math.min(MAX_ANSWER_PAUSE_SECONDS, Math.max(MIN_ANSWER_PAUSE_SECONDS, Math.ceil(waitMs / 1000)));
    lines.push({ text: line.text, pauseSeconds });
  }
  return { lines };
}
