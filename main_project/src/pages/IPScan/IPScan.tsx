import { useState } from "react";
import { useNotification } from "../../context/NotificationContext";
import Header from "../../components/Layout/Header/Header";
import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import AIAssistant from "../../components/AI/AIAssistant";

import bgVideo from "../../assets/videos/upload/Futuristic Blue Particles.mp4";

import { analyzeIP } from "../../services/ipAnalyzer";

function IPScan() {
  const { addNotification } = useNotification();

  const [ip, setIp] = useState("");

  const [result, setResult] = useState("");

  const analyze = () => {

    if (!ip.trim()) {

      alert("Please enter an IP Address.");

      return;

    }

    const output = analyzeIP(ip);

if (output.includes("INVALID")) {

  addNotification(
    "🚨 Invalid IP Address",
    "The entered IP address is invalid.",
    "critical"
  );

}
else if (output.includes("SUSPICIOUS")) {

  addNotification(
    "⚠️ Suspicious IP",
    "The IP address appears suspicious.",
    "warning"
  );

}
else if (output.includes("WARNING")) {

  addNotification(
    "🟡 Warning",
    "The IP address requires further verification.",
    "warning"
  );

}
else {

  addNotification(
    "✅ Safe IP Address",
    "The IP address appears safe.",
    "success"
  );

}


    setResult(output);

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
            {/* ================= HERO ================= */}

<h1 className="text-5xl font-bold text-white">

Enterprise IP Address Scanner

</h1>

<p className="mt-4 text-lg text-slate-300">

Analyze IPv4 addresses for security risks, private/public classification,
loopback detection and enterprise threat assessment.

</p>

{/* ================= INPUT CARD ================= */}

<div className="mt-10 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8 shadow-2xl">

<div className="flex items-center justify-between">

<div>

<h2 className="text-2xl font-bold text-white">

Paste IP Address

</h2>

<p className="mt-2 text-slate-400">

Supports IPv4 Address Analysis

</p>

</div>

<div className="rounded-full bg-cyan-500/10 px-5 py-2">

<span className="font-semibold text-cyan-400">

Enterprise AI Ready

</span>

</div>

</div>

<input

value={ip}

onChange={(e)=>setIp(e.target.value)}

placeholder="Example : 8.8.8.8"

className="mt-8 w-full rounded-2xl border border-cyan-500/20 bg-[#0F172A] p-5 text-white outline-none placeholder:text-slate-500"

/>

<button

onClick={analyze}

className="mt-8 rounded-2xl bg-cyan-500 px-10 py-4 font-semibold text-white transition hover:bg-cyan-600"

>

Analyze IP Address

</button>

<div className="mt-8 grid grid-cols-4 gap-6">

<div className="rounded-2xl bg-[#162033] p-5">

<h3 className="text-lg font-semibold text-cyan-400">

Public IP

</h3>

<p className="mt-2 text-sm text-slate-400">

Internet Accessible

</p>

</div>

<div className="rounded-2xl bg-[#162033] p-5">

<h3 className="text-lg font-semibold text-green-400">

Private IP

</h3>

<p className="mt-2 text-sm text-slate-400">

Internal Network

</p>

</div>

<div className="rounded-2xl bg-[#162033] p-5">

<h3 className="text-lg font-semibold text-yellow-400">

Loopback

</h3>

<p className="mt-2 text-sm text-slate-400">

127.0.0.1

</p>

</div>

<div className="rounded-2xl bg-[#162033] p-5">

<h3 className="text-lg font-semibold text-red-400">

Threat Score

</h3>

<p className="mt-2 text-sm text-slate-400">

Enterprise Analysis

</p>

</div>

</div>

</div>
{/* ================= IP DETAILS & AI ANALYSIS ================= */}

<div className="mt-10 grid grid-cols-12 gap-6">

  {/* IP Details */}

  <div className="col-span-5 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

    <h2 className="text-2xl font-bold text-white">

      IP Address Details

    </h2>

    <div className="mt-8 space-y-5">

      <div className="flex justify-between">

        <span className="text-slate-400">

          IP Address

        </span>

        <span className="text-white">

          {ip || "-"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          IP Version

        </span>

        <span className="text-cyan-400">

          IPv4

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Address Length

        </span>

        <span className="text-white">

          {ip.length}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          AI Engine

        </span>

        <span className="text-violet-400">

          Local IP Analyzer

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Scan Status

        </span>

        <span className="text-green-400">

          Ready

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

`Waiting for IP analysis...

Paste an IPv4 address and click "Analyze IP Address".

The Enterprise AI Engine will detect:

• Public IP
• Private IP
• Loopback Address
• Invalid IP
• Threat Score
• Risk Level
• Security Recommendation
• Enterprise Report`

}

      </pre>

    </div>

  </div>

</div>

{/* ================= ENTERPRISE SUMMARY ================= */}

<div className="mt-10 grid grid-cols-4 gap-6">

  <div className="rounded-[28px] border border-red-500/20 bg-[#101827]/90 p-6">

    <p className="text-slate-400">

      Threat Score

    </p>

    <h2 className="mt-3 text-4xl font-bold text-red-400">

      {result.match(/Threat Score\s*:\s*(\d+)%/)?.[1] || "0"}%

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

      IP Type

    </p>

    <h2 className="mt-3 text-2xl font-bold text-green-400">

      {result.match(/IP Type\s*:\s*(.*)/)?.[1] || "-"}

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

          Valid IPv4

        </span>

        <span className="text-green-400">

          {result.includes("INVALID") ? "NO" : "YES"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Private Address

        </span>

        <span className="text-yellow-400">

          {result.includes("Private") ? "YES" : "NO"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Loopback Address

        </span>

        <span className="text-orange-400">

          {result.includes("Loopback") ? "YES" : "NO"}

        </span>

      </div>

      <div className="flex justify-between">

        <span className="text-slate-400">

          Public Address

        </span>

        <span className="text-cyan-400">

          {result.includes("Public") ||
          result.includes("Google DNS") ||
          result.includes("Cloudflare DNS")
            ? "YES"
            : "NO"}

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
          ? result.includes("INVALID")
            ? "Invalid IP address detected. Verify the format before scanning."
            : result.includes("Private")
            ? "Private IP detected. This address belongs to an internal network and is not publicly routable."
            : result.includes("Loopback")
            ? "Loopback IP detected. Used for local device communication."
            : "Public IP appears safe based on current offline analysis."
          : "Analyze an IP address to receive AI-powered recommendations."}

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

    {["IP Submitted","Validation","Classification","Threat Analysis","Final Report"].map((step,index)=>(

      <div key={step}>

        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold">

          {index+1}

        </div>

        <p className="mt-4 text-slate-300">

          {step}

        </p>

      </div>

    ))}

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
result.includes("INVALID")
?"bg-red-500/20 text-red-400"
:result.includes("SUSPICIOUS")
?"bg-orange-500/20 text-orange-400"
:result.includes("WARNING")
?"bg-yellow-500/20 text-yellow-400"
:"bg-green-500/20 text-green-400"

}`}

    >

      {

result.includes("INVALID")

?"🚨 INVALID"

:result.includes("SUSPICIOUS")

?"⚠ SUSPICIOUS"

:result.includes("WARNING")

?"🟡 WARNING"

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

export default IPScan;