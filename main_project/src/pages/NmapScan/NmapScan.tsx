import { useState } from "react";
import {
  Search,
  Shield,
  Server,
  Network,
  Monitor,
  AlertTriangle,
} from "lucide-react";

import bgVideo from "../../assets/videos/api/Hologram HUD Animation.mp4";
import { useNotification } from "../../context/NotificationContext";
function NmapScan() {
  const { addNotification } = useNotification();
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [showResult, setShowResult] = useState(false);

  const startScan = () => {
    if (!target.trim()) {
      alert("Please enter a Target IP Address");
      return;
    }

    setLoading(true);
    setShowResult(false);

    setTimeout(() => {
  setLoading(false);
  setShowResult(true);

  addNotification(
    "⚠️ Medium Risk Host",
    "Nmap scan completed. 4 open ports were detected. Review exposed services.",
    "warning"
  );

}, 2500);
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#060B18] text-white">

      {/* Background Video */}

      <video
        autoPlay
        loop
        muted
        playsInline
        className="absolute inset-0 h-full w-full object-cover opacity-20"
      >
        <source src={bgVideo} type="video/mp4" />
      </video>

      <div className="absolute inset-0 bg-[#060B18]/75" />

      <div className="relative z-10 ml-[88px] px-14 py-12">

        <div className="mx-auto max-w-[1500px]">

          {/* Heading */}

          <div className="mb-10">

            <h1 className="text-4xl font-bold text-cyan-400">
              Nmap Network Scanner
            </h1>

            <p className="mt-2 text-slate-400">
              Scan a target host to discover open ports, services and operating
              system information.
            </p>

          </div>

          {/* Input */}

          <div className="rounded-3xl border border-cyan-500/20 bg-[#111827]/80 p-8 backdrop-blur-lg">

            <label className="mb-3 block text-lg font-semibold">
              Target IP Address
            </label>

            <div className="flex gap-4">

              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Example : 192.168.1.100"
                className="flex-1 rounded-xl border border-slate-700 bg-[#0B1220] px-5 py-4 text-white outline-none focus:border-cyan-500"
              />

              <button
                onClick={startScan}
                className="flex items-center gap-2 rounded-xl bg-cyan-600 px-8 font-semibold transition hover:bg-cyan-500"
              >
                <Search size={20} />
                Scan
              </button>

            </div>

          </div>

          {loading && (

            <div className="mt-8 rounded-2xl bg-[#111827] p-8 text-center">

              <Network
                size={50}
                className="mx-auto mb-4 animate-pulse text-cyan-400"
              />

              <h2 className="text-2xl font-bold">
                Running Nmap Scan...
              </h2>

              <p className="mt-2 text-slate-400">
                Discovering hosts and open ports...
              </p>

            </div>

          )}

          {showResult && (

            <div className="mt-8 space-y-8">

              {/* Summary */}

              <div className="grid gap-6 md:grid-cols-4">

                <div className="rounded-2xl bg-[#111827]/90 p-6">

                  <Shield className="mb-4 text-green-400" />

                  <h3 className="text-slate-400">
                    Host Status
                  </h3>

                  <p className="mt-2 text-2xl font-bold text-green-400">
                    ONLINE
                  </p>

                </div>

                <div className="rounded-2xl bg-[#111827]/90 p-6">

                  <Monitor className="mb-4 text-cyan-400" />

                  <h3 className="text-slate-400">
                    Operating System
                  </h3>

                  <p className="mt-2 text-xl font-bold">
                    Ubuntu Linux
                  </p>

                </div>

                <div className="rounded-2xl bg-[#111827]/90 p-6">

                  <Server className="mb-4 text-yellow-400" />

                  <h3 className="text-slate-400">
                    Open Ports
                  </h3>

                  <p className="mt-2 text-2xl font-bold">
                    4
                  </p>

                </div>

                <div className="rounded-2xl bg-[#111827]/90 p-6">

                  <AlertTriangle className="mb-4 text-orange-400" />

                  <h3 className="text-slate-400">
                    Risk Level
                  </h3>

                  <p className="mt-2 text-2xl font-bold text-orange-400">
                    Medium
                  </p>

                </div>

              </div>

              {/* Ports */}

              <div className="rounded-3xl bg-[#111827]/90 p-8">

                <h2 className="mb-6 text-2xl font-bold text-cyan-400">
                  Open Ports
                </h2>

                <table className="w-full">

                  <thead>

                    <tr className="border-b border-slate-700 text-left">

                      <th className="pb-3">Port</th>
                      <th>Service</th>
                      <th>Status</th>

                    </tr>

                  </thead>

                  <tbody>

                    <tr className="border-b border-slate-800">

                      <td className="py-4">22</td>
                      <td>SSH</td>
                      <td className="text-green-400">OPEN</td>

                    </tr>

                    <tr className="border-b border-slate-800">

                      <td className="py-4">80</td>
                      <td>HTTP</td>
                      <td className="text-green-400">OPEN</td>

                    </tr>

                    <tr className="border-b border-slate-800">

                      <td className="py-4">443</td>
                      <td>HTTPS</td>
                      <td className="text-green-400">OPEN</td>

                    </tr>

                    <tr>

                      <td className="py-4">3306</td>
                      <td>MySQL</td>
                      <td className="text-green-400">OPEN</td>

                    </tr>

                  </tbody>

                </table>

              </div>

              {/* AI Recommendation */}

              <div className="rounded-3xl border border-cyan-500/30 bg-cyan-900/20 p-8">

                <h2 className="mb-4 text-2xl font-bold text-cyan-300">
                  AI Security Recommendations
                </h2>

                <ul className="space-y-3 text-slate-300">

                  <li>✔ Close unused ports.</li>

                  <li>✔ Enable Firewall protection.</li>

                  <li>✔ Disable Telnet service.</li>

                  <li>✔ Update SSH to the latest version.</li>

                  <li>✔ Perform regular vulnerability scans.</li>

                </ul>

              </div>

            </div>

          )}

        </div>

      </div>

    </div>
  );
}

export default NmapScan;