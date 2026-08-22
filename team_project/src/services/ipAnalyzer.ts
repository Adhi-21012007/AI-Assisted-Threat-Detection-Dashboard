export function analyzeIP(ip: string): string {

  const value = ip.trim();

  let score = 0;

  const detected: string[] = [];

  const ipv4Regex =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  if (!ipv4Regex.test(value)) {

    return `

==================================================

        ENTERPRISE IP ANALYSIS

==================================================

Threat Score : 100%

Status : INVALID

Risk Level : CRITICAL

--------------------------------------------------

Reason

The entered value is not a valid IPv4 address.

--------------------------------------------------

Recommendation

Please enter a valid IPv4 address such as:

8.8.8.8
1.1.1.1
192.168.1.1

==================================================

`;

  }

  const parts = value.split(".").map(Number);

  const [a, b] = parts;

  let ipType = "Public";

  if (a === 10) {

    ipType = "Private";
    score += 10;
    detected.push("Private Network (10.x.x.x)");

  }

  else if (a === 172 && b >= 16 && b <= 31) {

    ipType = "Private";
    score += 10;
    detected.push("Private Network (172.16.x.x - 172.31.x.x)");

  }

  else if (a === 192 && b === 168) {

    ipType = "Private";
    score += 10;
    detected.push("Private Network (192.168.x.x)");

  }

  else {

    detected.push("Public IP Address");

  }
    if (a === 127) {

    score += 20;
    detected.push("Loopback Address");
    ipType = "Loopback";

  }

  if (a === 169 && b === 254) {

    score += 15;
    detected.push("Link Local Address");
    ipType = "Link Local";

  }

  if (a >= 224 && a <= 239) {

    score += 30;
    detected.push("Multicast Address");
    ipType = "Multicast";

  }

  if (a >= 240) {

    score += 40;
    detected.push("Reserved Address");
    ipType = "Reserved";

  }

  if (value === "0.0.0.0") {

    score += 50;
    detected.push("Unspecified Address");
    ipType = "Unspecified";

  }

  if (value === "255.255.255.255") {

    score += 40;
    detected.push("Broadcast Address");
    ipType = "Broadcast";

  }

  if (value === "8.8.8.8" || value === "8.8.4.4") {

    detected.push("Google Public DNS");

  }

  if (value === "1.1.1.1" || value === "1.0.0.1") {

    detected.push("Cloudflare Public DNS");

  }

  if (value === "9.9.9.9") {

    detected.push("Quad9 Secure DNS");

  }

  if (value === "208.67.222.222" || value === "208.67.220.220") {

    detected.push("OpenDNS");

  }
    if (detected.includes("Public IP Address")) {

    score = Math.max(0, score - 5);

  }

  if (score > 100) {

    score = 100;

  }

  if (score < 0) {

    score = 0;

  }

  let status = "SAFE";

  let level = "LOW";

  let recommendation =
    "This IP address appears safe based on local enterprise analysis.";

  if (score >= 80) {

    status = "SUSPICIOUS";

    level = "CRITICAL";

    recommendation =
      "This IP belongs to a reserved or highly unusual address range. Verify before using.";

  }

  else if (score >= 60) {

    status = "WARNING";

    level = "HIGH";

    recommendation =
      "This IP contains multiple suspicious characteristics. Further investigation is recommended.";

  }

  else if (score >= 40) {

    status = "WARNING";

    level = "MEDIUM";

    recommendation =
      "Exercise caution while communicating with this IP address.";

  }

  else if (score >= 20) {

    status = "LOW RISK";

    level = "LOW";

    recommendation =
      "The IP address is valid but belongs to a special-purpose network.";

  }

  else {

    status = "SAFE";

    level = "LOW";

    recommendation =
      "No suspicious characteristics were detected.";

  }
    return `

==================================================

        ENTERPRISE IP ANALYSIS REPORT

==================================================

Threat Score : ${score}%

Status : ${status}

Risk Level : ${level}

IP Type : ${ipType}

--------------------------------------------------

Detected Indicators

${
  detected.length > 0
    ? detected.map((item) => `• ${item}`).join("\n")
    : "No indicators detected."
}

--------------------------------------------------

Network Information

IP Address : ${value}

Version : IPv4

Octets : ${parts.join(" | ")}

--------------------------------------------------

Security Recommendation

${recommendation}

--------------------------------------------------

Enterprise AI Verdict

${
  status === "SAFE"
    ? "🟢 SAFE - No suspicious behaviour detected."
    : status === "LOW RISK"
    ? "🟡 LOW RISK - Special-purpose or internal network."
    : status === "WARNING"
    ? "🟠 WARNING - Review before allowing communication."
    : "🔴 SUSPICIOUS - Block or investigate immediately."
}

==================================================

`;

}