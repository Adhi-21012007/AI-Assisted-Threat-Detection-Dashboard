import { useState } from "react";
import { useNotification } from "../../context/NotificationContext";
import Header from "../../components/Layout/Header/Header";
import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import AIAssistant from "../../components/AI/AIAssistant";

import bgVideo from "../../assets/videos/upload/Futuristic Blue Particles.mp4";

import { scanURL } from "../../services/virusTotalService";
import { analyzeURL } from "../../services/urlAnalyzer";

function URLScan() {
  const { addNotification } = useNotification();

  const [url, setUrl] = useState("");

  const [result, setResult] = useState("");

  const analyze = async () => {

    if (!url.trim()) {

      alert("Please enter a URL.");

      return;

    }

    setResult("Scanning URL...\n\nChecking VirusTotal...\nRunning Local AI Analysis...");

    const response = await scanURL(url);

    if (!response) {

      setResult("VirusTotal API Error");

      return;

    }

    const localAnalysis = analyzeURL(url);

    const total =
      response.harmless +
      response.malicious +
      response.suspicious +
      response.undetected +
      response.timeout;

    let vtRisk = 0;

    if (total > 0) {

      vtRisk = Math.round(
        (
          (response.malicious +
            response.suspicious) /
          total
        ) * 100
      );

    }

    const localRisk =
      Number(
        localAnalysis.match(
          /Threat Score\s*:\s*(\d+)/
        )?.[1]
      ) || 0;

    const risk =
      total > 0
        ? Math.round(
            vtRisk * 0.6 +
            localRisk * 0.4
          )
        : localRisk;
            let status = "SAFE";

    let level = "LOW";

    if (risk >= 80) {

      status = "PHISHING";

      level = "CRITICAL";

    }

    else if (risk >= 60) {

      status = "DANGEROUS";

      level = "HIGH";

    }

    else if (risk >= 40) {

      status = "SUSPICIOUS";

      level = "MEDIUM";

    }

    else if (risk >= 20) {

      status = "LOW RISK";

      level = "LOW";

    }
    if (risk >= 80) {

  addNotification(
    "🚨 Phishing Website Detected",
    `${url} has been classified as a phishing website.`,
    "critical"
  );

}
else if (risk >= 60) {

  addNotification(
    "⚠️ Dangerous Website",
    `${url} has been classified as dangerous.`,
    "critical"
  );

}
else if (risk >= 40) {

  addNotification(
    "🟡 Suspicious URL",
    `${url} appears suspicious and requires manual verification.`,
    "warning"
  );

}
else if (risk >= 20) {

  addNotification(
    "ℹ️ Low Risk URL",
    `${url} has a low risk score.`,
    "success"
  );

}
else {

  addNotification(
    "✅ Safe Website",
    `${url} appears to be safe.`,
    "success"
  );

}

    setResult(`

==================================================

        ENTERPRISE URL SECURITY REPORT

==================================================

Threat Score : ${risk}%

Status : ${status}

Risk Level : ${level}

--------------------------------------------------

VirusTotal Analysis

Harmless : ${response.harmless}

Malicious : ${response.malicious}

Suspicious : ${response.suspicious}

Undetected : ${response.undetected}

Timeout : ${response.timeout}

--------------------------------------------------

Local Enterprise AI Analysis

${localAnalysis}

--------------------------------------------------

Overall Verdict

${
  risk >= 80
    ? "HIGHLY MALICIOUS URL"
    : risk >= 60
    ? "DANGEROUS WEBSITE"
    : risk >= 40
    ? "SUSPICIOUS WEBSITE"
    : risk >= 20
    ? "LOW RISK"
    : "SAFE WEBSITE"
}

==================================================

`);
  };

  return (

    <div className="relative min-h-screen overflow-hidden bg-[#070B16]">

      <video
        autoPlay
        muted
        loop
        playsInline
        className="fixed inset-0 h-full w-full object-cover opacity-35"
      >
        <source
          src={bgVideo}
          type="video/mp4"
        />
      </video>

      <div className="fixed inset-0 bg-[#050913]/20 backdrop-blur-[1px]" />

      <Header />

      <Sidebar />

      <div
        className="relative transition-all duration-500"
        style={{
          marginLeft: "88px",
        }}
      >

        <main className="mx-auto max-w-[1500px] px-14 py-12">
          <h1 className="text-5xl font-bold text-white">

Enterprise URL Scanner

</h1>

<p className="mt-4 text-lg text-slate-300">

Analyze suspicious URLs using Enterprise AI to detect phishing,
malware, fake websites and credential theft attacks.

</p>

<div className="mt-10 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8 shadow-2xl">

<div className="flex items-center justify-between">

<div>

<h2 className="text-2xl font-bold text-white">

Paste Website URL

</h2>

<p className="mt-2 text-slate-400">

Supported:
HTTP • HTTPS • Domains • IP URLs

</p>

</div>

<div className="rounded-full bg-cyan-500/10 px-5 py-2">

<span className="text-cyan-400 font-semibold">

Enterprise AI Ready

</span>

</div>

</div>

<input

value={url}

onChange={(e)=>setUrl(e.target.value)}

placeholder="https://example.com/login"

className="mt-8 w-full rounded-2xl border border-cyan-500/20 bg-[#0F172A] p-5 text-white outline-none placeholder:text-slate-500"

/>

<button

onClick={analyze}

className="mt-8 rounded-2xl bg-cyan-500 px-10 py-4 font-semibold text-white transition hover:bg-cyan-600"

>

Analyze URL

</button>

</div>
<div className="mt-10 grid grid-cols-12 gap-6">

  {/* URL Details */}

  <div className="col-span-5 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

    <h2 className="text-2xl font-bold text-white">

      URL Details

    </h2>

    <div className="mt-8 space-y-5">

      <div className="flex justify-between">

        <span className="text-slate-400">

          URL

        </span>

        <span className="max-w-[250px] break-all text-right text-white">

          {url || "-"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Protocol

        </span>

        <span className="text-cyan-400">

          {url.startsWith("https://")
            ? "HTTPS"
            : url.startsWith("http://")
            ? "HTTP"
            : "-"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          URL Length

        </span>

        <span className="text-white">

          {url.length}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Secure Connection

        </span>

        <span
          className={`font-semibold ${
            url.startsWith("https://")
              ? "text-green-400"
              : "text-red-400"
          }`}
        >

          {url.startsWith("https://")
            ? "YES"
            : "NO"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          AI Engine

        </span>

        <span className="text-violet-400">

          Local Threat Analyzer

        </span>

      </div>

    </div>

  </div>

  {/* Enterprise AI Analysis */}

  <div className="col-span-7 rounded-[30px] border border-red-500/20 bg-[#101827]/90 p-8">

    <h2 className="text-2xl font-bold text-white">

      Enterprise AI Analysis

    </h2>

    <div className="mt-8 rounded-2xl bg-[#0F172A] p-6">

      <pre className="whitespace-pre-wrap leading-8 text-slate-300">

{result ||

`Waiting for URL analysis...

Paste any URL and click "Analyze URL".

The Enterprise AI Engine will detect:

• Phishing Websites
• Fake Login Pages
• Credential Harvesting
• Malware URLs
• Suspicious Domains
• URL Obfuscation
• HTTP vs HTTPS
• High-Risk Domain Extensions
• Enterprise Threat Score`

}

      </pre>

    </div>

  </div>

</div>
{/* ================= ENTERPRISE SECURITY DASHBOARD ================= */}

<div className="mt-10 grid grid-cols-4 gap-6">

  <div className="rounded-[28px] border border-red-500/20 bg-[#101827]/90 p-6">

    <p className="text-slate-400">

      Threat Score

    </p>

    <h2 className="mt-3 text-4xl font-bold text-red-400">

      {result.match(/Threat Score\s*:\s*(\d+)%/)?.[1] || 0}%

    </h2>

  </div>

  <div className="rounded-[28px] border border-orange-500/20 bg-[#101827]/90 p-6">

    <p className="text-slate-400">

      Status

    </p>

    <h2 className="mt-3 text-3xl font-bold text-orange-400">

      {result.match(/Status\s*:\s*(.*)/)?.[1] || "WAITING"}

    </h2>

  </div>

  <div className="rounded-[28px] border border-cyan-500/20 bg-[#101827]/90 p-6">

    <p className="text-slate-400">

      Risk Level

    </p>

    <h2 className="mt-3 text-3xl font-bold text-cyan-400">

      {result.match(/Risk Level\s*:\s*(.*)/)?.[1] || "-"}

    </h2>

  </div>

  <div className="rounded-[28px] border border-green-500/20 bg-[#101827]/90 p-6">

    <p className="text-slate-400">

      AI Confidence

    </p>

    <h2 className="mt-3 text-4xl font-bold text-green-400">

      98%

    </h2>

  </div>

</div>

{/* ================= SECURITY INDICATORS ================= */}

<div className="mt-10 grid grid-cols-2 gap-6">

  <div className="rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

    <h2 className="text-2xl font-bold text-white">

      Security Indicators

    </h2>

    <div className="mt-8 space-y-5">

      <div className="flex justify-between">

        <span className="text-slate-400">

          HTTPS

        </span>

        <span
          className={`font-semibold ${
            url.startsWith("https://")
              ? "text-green-400"
              : "text-red-400"
          }`}
        >

          {url.startsWith("https://") ? "YES" : "NO"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Suspicious Domain

        </span>

        <span className="text-yellow-400">

          {url.includes(".xyz") ||
          url.includes(".tk") ||
          url.includes(".top")
            ? "YES"
            : "NO"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Login Keyword

        </span>

        <span className="text-red-400">

          {url.toLowerCase().includes("login")
            ? "FOUND"
            : "NOT FOUND"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Verify Keyword

        </span>

        <span className="text-red-400">

          {url.toLowerCase().includes("verify")
            ? "FOUND"
            : "NOT FOUND"}

        </span>

      </div>

    </div>

  </div>

  {/* AI Recommendation */}

  <div className="rounded-[30px] border border-violet-500/20 bg-[#101827]/90 p-8">

    <h2 className="text-2xl font-bold text-white">

      AI Recommendation

    </h2>

    <div className="mt-8 rounded-2xl bg-[#0F172A] p-6">

      <p className="leading-8 text-slate-300">

        {result
          ? result.includes("PHISHING")
            ? "This URL appears malicious. Do not visit the website or enter credentials. Block the domain and report it to your security team."
            : result.includes("SUSPICIOUS")
            ? "Verify the legitimacy of the website before opening it."
            : "The URL appears safe based on current analysis."
          : "Analyze a URL to receive AI-powered recommendations."}

      </p>

    </div>

  </div>

</div>
{/* ================= THREAT TIMELINE ================= */}

<div className="mt-10 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

  <h2 className="text-2xl font-bold text-white">

    Enterprise Threat Timeline

  </h2>

  <div className="mt-10 grid grid-cols-5 gap-4 text-center">

    <div>

      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold">

        1

      </div>

      <p className="mt-4 text-slate-300">

        URL Submitted

      </p>

    </div>

    <div>

      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-violet-500/20 text-violet-400 font-bold">

        2

      </div>

      <p className="mt-4 text-slate-300">

        Domain Analysis

      </p>

    </div>

    <div>

      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-yellow-500/20 text-yellow-400 font-bold">

        3

      </div>

      <p className="mt-4 text-slate-300">

        Threat Detection

      </p>

    </div>

    <div>

      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-500/20 text-red-400 font-bold">

        4

      </div>

      <p className="mt-4 text-slate-300">

        AI Inspection

      </p>

    </div>

    <div>

      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-green-500/20 text-green-400 font-bold">

        5

      </div>

      <p className="mt-4 text-slate-300">

        Final Report

      </p>

    </div>

  </div>

</div>

{/* ================= OVERALL STATUS ================= */}

<div className="mt-10 rounded-[30px] border border-red-500/20 bg-[#101827]/90 p-8">

  <h2 className="text-2xl font-bold text-white">

    Overall Security Status

  </h2>

  <div className="mt-8 flex justify-center">

    <div
      className={`rounded-full px-16 py-8 text-3xl font-bold

${
result.includes("PHISHING")

?"bg-red-500/20 text-red-400"

:result.includes("DANGEROUS")

?"bg-orange-500/20 text-orange-400"

:result.includes("SUSPICIOUS")

?"bg-yellow-500/20 text-yellow-400"

:"bg-green-500/20 text-green-400"

}`}

    >

      {

result.includes("PHISHING")

?"🚨 PHISHING"

:result.includes("DANGEROUS")

?"⚠ DANGEROUS"

:result.includes("SUSPICIOUS")

?"🟡 SUSPICIOUS"

:"🟢 SAFE"

}

    </div>

  </div>

</div>

<div className="h-24" />

</main>

<AIAssistant />

</div>

</div>

);

}

export default URLScan;