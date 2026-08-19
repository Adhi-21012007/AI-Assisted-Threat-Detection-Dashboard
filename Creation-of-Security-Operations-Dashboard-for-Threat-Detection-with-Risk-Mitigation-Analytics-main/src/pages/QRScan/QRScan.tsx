import { useState } from "react";

import { Html5QrcodeScanner } from "html5-qrcode";

import Header from "../../components/Layout/Header/Header";
import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import AIAssistant from "../../components/AI/AIAssistant";

import bgVideo from "../../assets/videos/upload/Futuristic Blue Particles.mp4";
import { useNotification } from "../../context/NotificationContext";
import { analyzeQR } from "../../services/qrAnalyzer";
import { analyzeURL } from "../../services/urlAnalyzer";

function QRScan() {
  const { addNotification } = useNotification();

  const [result, setResult] = useState("");

  const [content, setContent] = useState("");

  const startScanner = () => {

    const scanner = new Html5QrcodeScanner(

      "reader",

      {

        fps: 10,

        qrbox: {

          width: 250,

          height: 250,

        },

      },

      false

    );

    scanner.render(
  (decodedText) => {

    scanner.clear();

    setContent(decodedText);

    let report = analyzeQR(decodedText);

    if (
      decodedText.startsWith("http://") ||
      decodedText.startsWith("https://")
    ) {

      report += "\n\n" + analyzeURL(decodedText);

    }

    // Notifications
    if (report.includes("PHISHING")) {

      addNotification(
        "🚨 Phishing QR Code",
        "The scanned QR code contains a phishing website.",
        "critical"
      );

    }
    else if (report.includes("DANGEROUS")) {

      addNotification(
        "🔴 Dangerous QR Code",
        "The scanned QR code contains dangerous content.",
        "critical"
      );

    }
    else if (report.includes("SUSPICIOUS")) {

      addNotification(
        "⚠️ Suspicious QR Code",
        "The scanned QR code appears suspicious.",
        "warning"
      );

    }
    else {

      addNotification(
        "✅ Safe QR Code",
        "The scanned QR code appears safe.",
        "success"
      );

    }

    setResult(report);

  },
  () => {}
);

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
        <source src={bgVideo} type="video/mp4" />
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
            Enterprise QR Code Scanner
          </h1>

          <p className="mt-4 text-lg text-slate-300">
            Scan QR codes using your camera and automatically detect URLs,
            Emails, Phone Numbers, Wi-Fi credentials, SMS and potential
            phishing attacks with Enterprise AI.
          </p>

          {/* ================= SCANNER ================= */}

          <div className="mt-10 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8 shadow-2xl">

            <div className="flex items-center justify-between">

              <div>

                <h2 className="text-2xl font-bold text-white">
                  Live QR Scanner
                </h2>

                <p className="mt-2 text-slate-400">
                  Click Start Scanner and point your camera at a QR Code.
                </p>

              </div>

              <div className="rounded-full bg-cyan-500/10 px-5 py-2">

                <span className="font-semibold text-cyan-400">
                  Enterprise AI Ready
                </span>

              </div>

            </div>

            <button
              onClick={startScanner}
              className="mt-8 rounded-2xl bg-cyan-500 px-10 py-4 font-semibold text-white transition hover:bg-cyan-600"
            >
              Start QR Scanner
            </button>

            <div
              id="reader"
              className="mt-8 overflow-hidden rounded-2xl border border-cyan-500/20"
            />

          </div>

          {/* ================= QR DETAILS ================= */}

          <div className="mt-10 grid grid-cols-12 gap-6">

            <div className="col-span-5 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

              <h2 className="text-2xl font-bold text-white">
                QR Details
              </h2>

              <div className="mt-8 space-y-5">

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    Scan Status
                  </span>

                  <span className="text-green-400">
                    {content ? "Completed" : "Waiting"}
                  </span>

                </div>

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    Content Length
                  </span>

                  <span className="text-white">
                    {content.length}
                  </span>

                </div>

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    AI Engine
                  </span>

                  <span className="text-violet-400">
                    Enterprise QR Analyzer
                  </span>

                </div>

              </div>

            </div>

            <div className="col-span-7 rounded-[30px] border border-red-500/20 bg-[#101827]/90 p-8">

              <h2 className="text-2xl font-bold text-white">
                Enterprise AI Analysis
              </h2>

              <div className="mt-8 rounded-2xl bg-[#0F172A] p-6">

                <pre className="whitespace-pre-wrap leading-8 text-slate-300">

                  {result ||

`Waiting for QR Scan...

The Enterprise AI Engine will detect:

• URL
• Email
• Phone Number
• SMS
• Wi-Fi
• Plain Text
• Phishing QR Codes
• Threat Score
• AI Recommendation`}

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
                QR Type
              </p>

              <h2 className="mt-3 text-2xl font-bold text-green-400">
                {result.match(/QR Content Type\s*:\s*(.*)/)?.[1] || "-"}
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
                    URL Detected
                  </span>

                  <span className="text-cyan-400">
                    {content.startsWith("http") ? "YES" : "NO"}
                  </span>

                </div>

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    Email
                  </span>

                  <span className="text-green-400">
                    {content.startsWith("mailto:") ? "YES" : "NO"}
                  </span>

                </div>

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    Phone
                  </span>

                  <span className="text-yellow-400">
                    {content.startsWith("tel:") ? "YES" : "NO"}
                  </span>

                </div>

                <div className="flex justify-between">

                  <span className="text-slate-400">
                    Wi-Fi
                  </span>

                  <span className="text-violet-400">
                    {content.toLowerCase().startsWith("wifi:") ? "YES" : "NO"}
                  </span>

                </div>

              </div>

            </div>

            {/* ================= AI RECOMMENDATION ================= */}

            <div className="rounded-[30px] border border-violet-500/20 bg-[#101827]/90 p-8">

              <h2 className="text-2xl font-bold text-white">
                AI Recommendation
              </h2>

              <div className="mt-8 rounded-2xl bg-[#0F172A] p-6">

                <p className="leading-8 text-slate-300">

                  {result
                    ? result.includes("PHISHING")
                      ? "Do not open this QR code. It contains highly suspicious indicators."
                      : result.includes("DANGEROUS")
                      ? "Avoid interacting with the decoded content."
                      : result.includes("SUSPICIOUS")
                      ? "Verify the QR source before opening."
                      : "No major security issues detected."
                    : "Scan a QR Code to receive AI-powered recommendations."}

                </p>

              </div>

            </div>

          </div>
                    {/* ================= THREAT TIMELINE ================= */}

          <div className="mt-10 rounded-[30px] border border-cyan-500/20 bg-[#101827]/90 p-8">

            <h2 className="text-2xl font-bold text-white">
              Enterprise Scan Timeline
            </h2>

            <div className="mt-10 grid grid-cols-5 gap-4 text-center">

              {[
                "QR Detected",
                "Content Decoded",
                "Type Detection",
                "AI Analysis",
                "Final Report",
              ].map((step, index) => (

                <div key={step}>

                  <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyan-500/20 font-bold text-cyan-400">

                    {index + 1}

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
  result.includes("PHISHING")
    ? "bg-red-500/20 text-red-400"
    : result.includes("DANGEROUS")
    ? "bg-orange-500/20 text-orange-400"
    : result.includes("SUSPICIOUS")
    ? "bg-yellow-500/20 text-yellow-400"
    : "bg-green-500/20 text-green-400"
}`}

              >

                {
                  result.includes("PHISHING")
                    ? "🚨 PHISHING"
                    : result.includes("DANGEROUS")
                    ? "🔴 DANGEROUS"
                    : result.includes("SUSPICIOUS")
                    ? "⚠️ SUSPICIOUS"
                    : "🟢 SAFE"
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

export default QRScan;