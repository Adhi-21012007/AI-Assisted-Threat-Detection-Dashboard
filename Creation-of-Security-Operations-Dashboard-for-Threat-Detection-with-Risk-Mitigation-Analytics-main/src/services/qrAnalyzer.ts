export function analyzeQR(content: string): string {

  const value = content.trim();

  let score = 0;

  const detected: string[] = [];

  let type = "Unknown";

  let status = "SAFE";

  let level = "LOW";

  let recommendation = "No security issues detected.";

  const lower = value.toLowerCase();

  if (!value) {

    return `

==================================================

        ENTERPRISE QR ANALYSIS

==================================================

Status : INVALID

Reason : Empty QR Code

Recommendation :

Please upload or scan a valid QR Code.

==================================================

`;

  }

  if (

    lower.startsWith("http://") ||
    lower.startsWith("https://")

  ) {

    type = "URL";

    detected.push("Website URL");

  }

  else if (lower.startsWith("mailto:")) {

    type = "Email";

    detected.push("Email Address");

  }

  else if (lower.startsWith("tel:")) {

    type = "Phone";

    detected.push("Phone Number");

  }

  else if (lower.startsWith("smsto:")) {

    type = "SMS";

    detected.push("SMS Message");

  }

  else if (lower.startsWith("wifi:")) {

    type = "WiFi";

    detected.push("WiFi Configuration");

  }

  else {

    type = "Text";

    detected.push("Plain Text");

  }
    if (type === "URL") {

    if (lower.startsWith("http://")) {

      score += 20;
      detected.push("HTTP Connection");

    } else {

      detected.push("HTTPS Connection");

    }

    const keywords = [

      "login",
      "verify",
      "secure",
      "password",
      "account",
      "update",
      "bank",
      "paypal",
      "gift",
      "reward",
      "claim",
      "bonus",
      "otp",
      "wallet",
      "invoice",
      "free"

    ];

    keywords.forEach((word) => {

      if (lower.includes(word)) {

        score += 10;
        detected.push(`Keyword : ${word}`);

      }

    });

    const suspiciousTLD = [

      ".xyz",
      ".top",
      ".tk",
      ".ml",
      ".ga",
      ".cf",
      ".gq",
      ".click",
      ".work",
      ".zip"

    ];

    suspiciousTLD.forEach((ext) => {

      if (lower.includes(ext)) {

        score += 20;
        detected.push(`Suspicious TLD : ${ext}`);

      }

    });

    if (lower.includes("@")) {

      score += 20;
      detected.push("@ Redirect");

    }

    if (lower.length > 100) {

      score += 15;
      detected.push("Long URL");

    }

  }

  else if (type === "WiFi") {

    detected.push("Network Configuration");

    score += 5;

  }

  else if (type === "Email") {

    detected.push("Email Action");

  }

  else if (type === "Phone") {

    detected.push("Phone Call Action");

  }

  else if (type === "SMS") {

    detected.push("SMS Action");

  }

  else {

    detected.push("Plain Text Content");

  }
    if (score > 100) {
  score = 100;
}

if (score < 0) {
  score = 0;
}

if (score >= 80) {
  status = "PHISHING";
  level = "CRITICAL";
  recommendation =
    "This QR code contains a highly suspicious URL. Do not open it.";
} else if (score >= 60) {
  status = "DANGEROUS";
  level = "HIGH";
  recommendation =
    "The QR code contains multiple phishing indicators. Avoid scanning or opening it.";
} else if (score >= 40) {
  status = "SUSPICIOUS";
  level = "MEDIUM";
  recommendation =
    "Verify the QR code source before proceeding.";
} else if (score >= 20) {
  status = "LOW RISK";
  level = "LOW";
  recommendation =
    "The QR code contains a few suspicious characteristics.";
} else {
  status = "SAFE";
  level = "LOW";
  recommendation =
    "No suspicious indicators were detected.";
}

return `

==================================================

        ENTERPRISE QR ANALYSIS

==================================================

QR Content Type : ${type}

Detected Features :

${detected.map((d) => `• ${d}`).join("\n")}

--------------------------------------------------

Threat Score : ${score}%

Status : ${status}

Risk Level : ${level}

--------------------------------------------------

AI Recommendation :

${recommendation}

==================================================

`;

}