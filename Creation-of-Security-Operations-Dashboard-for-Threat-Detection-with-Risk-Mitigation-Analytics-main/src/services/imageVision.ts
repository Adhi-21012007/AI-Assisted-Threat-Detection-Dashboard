export async function analyzeImage(extractedText: string): Promise<string> {

  const text = extractedText.toLowerCase();
  if (!text.trim()) {

  return `
🟡 WARNING

Threat Score : 40%

Status : No Text Detected

Reason:
No readable text was found in the uploaded image.

Recommendation:
• Upload a clearer image.
• Ensure the image contains visible text.
`;

}

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
    { word: "job", score: 5 },
    { word: "sign in", score: 15 },
    { word: "authenticate", score: 20 },
    { word: "verification", score: 15 },
    { word: "reset password", score: 20 },
    { word: "update account", score: 20 },
    { word: "credit card", score: 20 },
    { word: "debit card", score: 20 },
    { word: "upi", score: 15 },
    { word: "cvv", score: 25 },
    { word: "aadhaar", score: 20 },
    { word: "pan", score: 15 },
    { word: "income tax", score: 15 },
    { word: "refund", score: 15 },
    { word: "reward", score: 15 },
    { word: "free", score: 10 },
    { word: "bitcoin", score: 20 },
    { word: "crypto", score: 20 },
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
This image contains multiple phishing or scam indicators.

Recommendation:
• Do NOT click any links.
• Do NOT enter credentials.
• Block the sender.
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
Potential phishing or social engineering content detected.

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
Image appears safe.
`;

}