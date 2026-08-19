// =====================================================
// AI Penetration Analyzer
// Part 1
// =====================================================

export interface PenetrationResult {
  report: string;
  score: number;
  status: string;
  risk: string;

  notificationTitle: string;
  notificationMessage: string;
  notificationType: "success" | "warning" | "critical";
}

interface ScanResult {
  openPorts: number[];
  vulnerabilities: string[];
  headers: string[];
  ssl: string;
}

function normalizeTarget(target: string): string {
  return target
    .replace("https://", "")
    .replace("http://", "")
    .replace("www.", "")
    .split("/")[0]
    .toLowerCase();
}
function getDomainSeed(domain: string): number {
  let seed = 0;

  for (let i = 0; i < domain.length; i++) {
    seed += domain.charCodeAt(i);
  }

  return seed;
}
function simulatePortScan(domain: string): number[] {

  const ports: number[] = [80, 443];

  if (
    domain.includes("google") ||
    domain.includes("amazon") ||
    domain.includes("github") ||
    domain.includes("microsoft")
  ) {
    return ports;
  }

  if (domain.includes("test")) {
    return [21, 22, 23, 80, 443, 3306];
  }

  if (domain.includes("demo")) {
    return [21, 23, 80, 139, 445, 3389];
  }

  const common = [22, 25, 53, 110, 143, 3306];

const seed = getDomainSeed(domain);

common.forEach((port, index) => {
  if ((seed + index) % 3 === 0) {
    ports.push(port);
  }
});

return [...new Set(ports)];
}

function checkSSL(domain: string): string {

  if (
    domain.includes("google") ||
    domain.includes("github") ||
    domain.includes("amazon")
  ) {
    return "Strong TLS 1.3";
  }

  if (domain.includes("demo")) {
    return "Weak TLS 1.0";
  }

  const seed = getDomainSeed(domain);

return seed % 2 === 0
  ? "TLS 1.3"
  : "TLS 1.2";
}

function analyzeHeaders(domain: string): string[] {

  const headers: string[] = [];

  if (
    domain.includes("google") ||
    domain.includes("amazon") ||
    domain.includes("github")
  ) {

    headers.push(
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "Referrer-Policy"
    );

  } else {

    headers.push(
      "X-Frame-Options",
      "X-Content-Type-Options"
    );

  }

  return headers;
}

function detectVulnerabilities(
  ports: number[],
  headers: string[],
  ssl: string
): string[] {

  const vulnerabilities: string[] = [];

  if (ports.includes(21))
    vulnerabilities.push("FTP service detected");

  if (ports.includes(23))
    vulnerabilities.push("Telnet service exposed");

  if (ports.includes(3306))
    vulnerabilities.push("MySQL database publicly accessible");

  if (ports.includes(445))
    vulnerabilities.push("SMB service exposed");

  if (ports.includes(3389))
    vulnerabilities.push("Remote Desktop exposed");

  if (!headers.includes("Content-Security-Policy"))
    vulnerabilities.push("Missing Content Security Policy");

  if (!headers.includes("Strict-Transport-Security"))
    vulnerabilities.push("Missing HSTS Header");

  if (ssl.includes("TLS 1.0"))
    vulnerabilities.push("Outdated TLS version");

  return vulnerabilities;
}

function performScan(domain: string): ScanResult {

  const openPorts = simulatePortScan(domain);

  const ssl = checkSSL(domain);

  const headers = analyzeHeaders(domain);

  const vulnerabilities = detectVulnerabilities(
    openPorts,
    headers,
    ssl
  );

  return {
    openPorts,
    vulnerabilities,
    headers,
    ssl
  };
}

// -------- CONTINUE IN PART 2 --------
// =====================================================
// AI Penetration Analyzer
// Part 2
// =====================================================

function calculateScore(scan: ScanResult): number {

  let score = 0;

  score += scan.vulnerabilities.length * 12;

  scan.openPorts.forEach((port) => {
    switch (port) {

      case 23:
        score += 20;
        break;

      case 21:
        score += 15;
        break;

      case 445:
        score += 18;
        break;

      case 3389:
        score += 18;
        break;

      case 3306:
        score += 15;
        break;

      case 22:
        score += 4;
        break;

      case 80:
        score += 1;
        break;

      case 443:
        score -= 5;
        break;
    }
  });

  if (scan.ssl.includes("TLS 1.3"))
    score -= 10;

  if (scan.ssl.includes("TLS 1.2"))
    score -= 5;

  if (scan.headers.length >= 4)
    score -= 10;

  score = Math.max(0, score);
  score = Math.min(100, score);

  return score;
}

function generateStatus(score: number): string {

  if (score <= 20) return "SAFE";
  if (score <= 40) return "LOW";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";

  return "CRITICAL";
}

function generateRisk(score: number): string {

  if (score <= 20) return "Low";
  if (score <= 40) return "Moderate";
  if (score <= 60) return "Elevated";
  if (score <= 80) return "High";

  return "Critical";
}

// ===============================
// Dynamic Notification Generator
// ===============================

function generateNotification(status: string) {

  switch (status) {

    case "CRITICAL":
      return {
        notificationTitle: "🚨 Critical Vulnerability",
        notificationMessage:
          "Critical security vulnerabilities were detected during penetration testing.",
        notificationType: "critical" as const,
      };

    case "HIGH":
      return {
        notificationTitle: "🔴 High Risk Target",
        notificationMessage:
          "High-risk vulnerabilities were identified.",
        notificationType: "critical" as const,
      };

    case "MEDIUM":
      return {
        notificationTitle: "⚠️ Medium Risk Target",
        notificationMessage:
          "Several security issues require attention.",
        notificationType: "warning" as const,
      };

    case "LOW":
      return {
        notificationTitle: "🟡 Low Risk Target",
        notificationMessage:
          "Minor security weaknesses were detected.",
        notificationType: "warning" as const,
      };

    default:
      return {
        notificationTitle: "✅ Secure Target",
        notificationMessage:
          "Penetration testing completed successfully with minimal risk.",
        notificationType: "success" as const,
      };
  }
}

function generateExecutiveSummary(
  domain: string,
  scan: ScanResult,
  score: number,
  status: string
): string {

  return `
Executive Summary
=================

Target
------
${domain}

Overall Security Score
----------------------
${score}/100

Security Status
---------------
${status}

SSL Configuration
-----------------
${scan.ssl}

Open Ports
----------
${scan.openPorts.join(", ")}

Detected Vulnerabilities
------------------------
${scan.vulnerabilities.length}

Security Headers
----------------
${scan.headers.join(", ")}

`;
}

function generateRecommendations(scan: ScanResult): string {

  const recommendations: string[] = [];

  if (scan.vulnerabilities.some(v => v.includes("FTP")))
    recommendations.push("Disable public FTP access.");

  if (scan.vulnerabilities.some(v => v.includes("Telnet")))
    recommendations.push("Replace Telnet with SSH.");

  if (scan.vulnerabilities.some(v => v.includes("MySQL")))
    recommendations.push("Restrict database access using firewall rules.");

  if (scan.vulnerabilities.some(v => v.includes("SMB")))
    recommendations.push("Disable SMB exposure over the internet.");

  if (scan.vulnerabilities.some(v => v.includes("Remote Desktop")))
    recommendations.push("Restrict RDP access with VPN and MFA.");

  if (scan.vulnerabilities.some(v => v.includes("Content Security Policy")))
    recommendations.push("Configure Content-Security-Policy header.");

  if (scan.vulnerabilities.some(v => v.includes("HSTS")))
    recommendations.push("Enable Strict-Transport-Security header.");

  if (scan.vulnerabilities.some(v => v.includes("TLS")))
    recommendations.push("Upgrade to TLS 1.3.");

  if (recommendations.length === 0) {
    recommendations.push("No critical issues detected.");
    recommendations.push("Continue periodic penetration testing.");
    recommendations.push("Keep all systems patched.");
  }

  return recommendations
    .map((item, index) => `${index + 1}. ${item}`)
    .join("\n");
}

// -------- CONTINUE IN PART 3 --------
// =====================================================
// AI Penetration Analyzer
// Part 3
// =====================================================

export function analyzeTarget(target: string): PenetrationResult {

  const domain = normalizeTarget(target);

  const scan = performScan(domain);

  const score = calculateScore(scan);

  const status = generateStatus(score);

  const risk = generateRisk(score);

  const notification = generateNotification(status);

  const recommendations = generateRecommendations(scan);

  const vulnerabilitySection =
    scan.vulnerabilities.length > 0
      ? scan.vulnerabilities
          .map((v, i) => `${i + 1}. ${v}`)
          .join("\n")
      : "No major vulnerabilities detected.";

  const report = `
====================================================
          AI PENETRATION TEST REPORT
====================================================

${generateExecutiveSummary(domain, scan, score, status)}

====================================================
OPEN PORTS
====================================================

${scan.openPorts.join(", ")}

====================================================
SECURITY HEADERS
====================================================

${scan.headers.join("\n")}

====================================================
VULNERABILITIES
====================================================

${vulnerabilitySection}

====================================================
AI RISK ANALYSIS
====================================================

Overall Risk Level : ${risk}

Overall Security Score : ${score}/100

Assessment:

${
  score <= 20
    ? "The target appears to follow good security practices. Only minor improvements are recommended."
    : score <= 40
    ? "Low-risk findings detected. Review the identified issues to strengthen security."
    : score <= 60
    ? "Several weaknesses were identified. Mitigation is recommended before production deployment."
    : score <= 80
    ? "High-risk configuration detected. Immediate remediation is recommended."
    : "Critical security weaknesses detected. Immediate investigation and remediation are required."
}

====================================================
AI RECOMMENDATIONS
====================================================

${recommendations}

====================================================
DISCLAIMER
====================================================

This report is generated by a simulated AI Penetration
Testing Engine for educational and demonstration
purposes. It does not perform live network attacks or
real exploitation of systems.

Generated by:
Enterprise AI Penetration Testing Module
`;

  return {
    report,
    score,
    status,
    risk,

    notificationTitle: notification.notificationTitle,
    notificationMessage: notification.notificationMessage,
    notificationType: notification.notificationType,
  };
}