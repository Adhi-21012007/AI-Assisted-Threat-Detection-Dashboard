export function analyzeText(extractedText: string): string {

  const text = extractedText.toLowerCase();

  let score = 0;

  const found: string[] = [];

  const keywords = [
    { word: "verify", score: 15 },
    { word: "account", score: 10 },
    { word: "login", score: 20 },
    { word: "password", score: 20 },
    { word: "otp", score: 20 },
    { word: "bank", score: 20 },
    { word: "paypal", score: 20 },
    { word: "gift", score: 15 },
    { word: "winner", score: 15 },
    { word: "claim", score: 15 },
    { word: "urgent", score: 15 },
    { word: "immediately", score: 15 },
    { word: "suspended", score: 20 },
    { word: "click here", score: 15 },
    { word: "confirm", score: 10 },
    { word: "credential", score: 20 },
    { word: "security alert", score: 15 },
    { word: "limited time", score: 10 },
    { word: "work from home", score: 15 },
    { word: "$75", score: 10 },
    { word: "selected", score: 10 },
    { word: "job", score: 5 }
  ];

  for (const item of keywords) {

    if (text.includes(item.word)) {

      score += item.score;

      found.push(item.word);

    }

  }

  if (score > 100) score = 100;

  if (score >= 80) {

    return `
🔴 HIGH RISK

Threat Score : ${score}%

Status : Phishing Detected

Detected Keywords:
${found.join(", ")}

Reason:
This message contains multiple phishing or scam indicators.

Recommendation:
• Do NOT click any links.
• Do NOT enter passwords or OTPs.
• Verify the sender.
• Report this message.
`;

  }

  if (score >= 40) {

    return `
🟡 WARNING

Threat Score : ${score}%

Status : Suspicious

Detected Keywords:
${found.join(", ")}

Reason:
Potential phishing or social engineering attempt detected.

Recommendation:
Verify the sender before taking any action.
`;

  }

  return `
🟢 SAFE

Threat Score : ${score}%

Status : Safe

Reason:
No significant phishing indicators detected.

Recommendation:
This message appears safe.
`;

}