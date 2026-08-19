export function analyzeURL(url: string): string {

  const value = url.trim().toLowerCase();

  let score = 0;

  const detected: string[] = [];

  let hostname = "";

  try {

    hostname = new URL(value).hostname.replace(/^www\./, "");

  } catch {

    score += 25;
    detected.push("Invalid URL");

  }

  const trustedDomains = [

    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "infosys.com",
    "openai.com",
    "linkedin.com",
    "oracle.com",
    "ibm.com",
    "cisco.com",
    "adobe.com",
    "stackoverflow.com",
    "youtube.com",
    "mozilla.org",
    "wikipedia.org",
    "reddit.com",
    "nvidia.com",

  ];

  const keywordWeight: Record<string, number> = {

    login: 15,
    verify: 15,
    secure: 10,
    bank: 20,
    update: 10,
    confirm: 10,
    password: 20,
    signin: 15,
    account: 15,
    wallet: 15,
    gift: 15,
    winner: 20,
    bonus: 15,
    claim: 15,
    otp: 20,
    free: 15,
    reward: 20,
    payment: 15,
    invoice: 15,
    paypal: 20,

  };

  const tldWeight: Record<string, number> = {

    ".xyz": 30,
    ".top": 25,
    ".tk": 35,
    ".ml": 30,
    ".ga": 30,
    ".cf": 30,
    ".gq": 30,
    ".click": 30,
    ".work": 25,
    ".zip": 30,

  };

  const trusted = trustedDomains.some(

    (domain) =>
      hostname === domain ||
      hostname.endsWith("." + domain)

  );

  if (trusted) {

    detected.push("Trusted Domain");

  }

  if (value.startsWith("https://")) {

    detected.push("HTTPS");

  } else {

    score += 20;
    detected.push("HTTP");

  }
    Object.entries(keywordWeight).forEach(([word, weight]) => {

    if (value.includes(word)) {

      score += weight;
      detected.push(word);

    }

  });

  Object.entries(tldWeight).forEach(([ext, weight]) => {

    if (value.includes(ext)) {

      score += weight;
      detected.push(ext);

    }

  });

  const ipRegex =
    /^https?:\/\/((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/;

  if (ipRegex.test(value)) {

    score += 40;
    detected.push("IP Address");

  }

  if (value.length > 80) {

    score += 15;
    detected.push("Long URL");

  }

  if (value.length > 120) {

    score += 20;
    detected.push("Very Long URL");

  }

  const shorteners = [

    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",

  ];

  if (shorteners.some(site => value.includes(site))) {

    score += 30;
    detected.push("Shortened URL");

  }

  if (value.includes("@")) {

    score += 30;
    detected.push("@ Redirect");

  }

  const hyphenCount = (value.match(/-/g) || []).length;

  if (hyphenCount >= 3) {

    score += 15;
    detected.push("Multiple Hyphens");

  }

  if (

    value.includes("redirect=") ||
    value.includes("url=") ||
    value.includes("next=")

  ) {

    score += 20;
    detected.push("Redirect Parameter");

  }
    if (value.includes("%")) {

    score += 10;
    detected.push("Encoded Characters");

  }

  if (value.includes("=")) {

    score += 5;
    detected.push("Query Parameters");

  }

  if (value.includes("_")) {

    score += 5;
    detected.push("Underscore");

  }

  const dotCount = (hostname.match(/\./g) || []).length;

  if (dotCount >= 3) {

    score += 15;
    detected.push("Multiple Subdomains");

  }

  const numberCount = (value.match(/\d/g) || []).length;

  if (numberCount >= 8) {

    score += 15;
    detected.push("Many Numbers");

  }

  if (trusted) {

    if (

      !value.includes("login") &&
      !value.includes("verify") &&
      !value.includes("secure") &&
      !value.includes("account") &&
      !value.includes("password")

    ) {

      score = Math.max(0, score - 20);

    }

  }

  if (score < 0) score = 0;

  if (score > 100) score = 100;

  let status = "SAFE";
  let level = "LOW";
  let recommendation = "Safe to visit.";

  if (score >= 80) {

    status = "PHISHING";
    level = "CRITICAL";
    recommendation =
      "This website appears highly malicious. Do not open it or enter any credentials.";

  } else if (score >= 60) {

    status = "DANGEROUS";
    level = "HIGH";
    recommendation =
      "Avoid visiting this website. It shows multiple phishing indicators.";

  } else if (score >= 40) {

    status = "SUSPICIOUS";
    level = "MEDIUM";
    recommendation =
      "Proceed with caution. Verify the website before continuing.";

  } else if (score >= 20) {

    status = "LOW RISK";
    level = "LOW";
    recommendation =
      "The website has a few suspicious characteristics. Stay alert.";

  } else {

    status = "SAFE";
    level = "LOW";
    recommendation =
      "No major phishing indicators were detected.";

  }
    return `

==================================================

        LOCAL AI URL ANALYSIS

==================================================

Threat Score : ${score}%

Status : ${status}

Risk Level : ${level}

--------------------------------------------------

Detected Indicators

${
  detected.length > 0
    ? detected.map((item) => `• ${item}`).join("\n")
    : "No suspicious indicators detected."
}

--------------------------------------------------

Recommendation

${recommendation}

--------------------------------------------------

Security Summary

Total Indicators Detected : ${detected.length}

Trusted Domain : ${trusted ? "YES" : "NO"}

Protocol : ${
  value.startsWith("https://")
    ? "HTTPS"
    : "HTTP"
}

Hostname : ${hostname || "Unknown"}

--------------------------------------------------

Enterprise AI Verdict

${
  score >= 80
    ? "🚨 High confidence phishing website. Block immediately."
    : score >= 60
    ? "⚠️ Dangerous website. Do not enter credentials."
    : score >= 40
    ? "⚠️ Suspicious website. Verify before visiting."
    : score >= 20
    ? "ℹ️ Low-risk website. Proceed carefully."
    : "✅ Website appears safe based on local AI analysis."
}

==================================================

`;

}