import { useNavigate } from "react-router-dom";
import { useUser } from "../../context/UserContext";

import welcomeVideo from "../../assets/videos/welcome/Cyber Security Background.mp4";

function Welcome() {
  const navigate = useNavigate();
  const { userName } = useUser();

  return (
    <div className="relative min-h-screen overflow-hidden">

      {/* Background Video */}

      <video
        autoPlay
        loop
        muted
        playsInline
        className="absolute inset-0 h-full w-full object-cover brightness-110 contrast-110"
      >
        <source
          src={welcomeVideo}
          type="video/mp4"
        />
      </video>

      {/* Overlay */}

      <div className="absolute inset-0 bg-slate-950/40"></div>

      {/* Content */}

      <div className="relative flex min-h-screen items-center justify-center px-6">

        <div className="w-full max-w-4xl rounded-3xl border border-cyan-400/30 bg-slate-900/40 backdrop-blur-xl p-12 shadow-2xl">

          <p className="uppercase tracking-[0.35em] text-cyan-400 font-semibold text-sm">
            AI Security Platform
          </p>

          <h1 className="mt-5 text-6xl font-extrabold text-white leading-tight">

            Welcome,

            <span className="block text-cyan-400 mt-2">

              {userName}

            </span>

          </h1>

          <p className="mt-6 text-2xl font-semibold text-slate-100">

            AI-Assisted Threat Detection Dashboard

          </p>

          <p className="mt-3 max-w-3xl text-lg leading-8 text-slate-300">

            Monitor, detect and respond to cyber threats using
            AI-powered analytics, Google Cloud services,
            threat intelligence and real-time monitoring.

          </p>

          {/* Status */}

          <div className="grid grid-cols-2 gap-5 mt-12">

            <div className="rounded-2xl bg-white/10 p-5 border border-white/10">

              <h3 className="text-green-400 font-bold">

                ● AI Engine

              </h3>

              <p className="text-slate-300 mt-2">

                Ready

              </p>

            </div>

            <div className="rounded-2xl bg-white/10 p-5 border border-white/10">

              <h3 className="text-green-400 font-bold">

                ● Google Cloud

              </h3>

              <p className="text-slate-300 mt-2">

                Connected

              </p>

            </div>

            <div className="rounded-2xl bg-white/10 p-5 border border-white/10">

              <h3 className="text-green-400 font-bold">

                ● Threat Intelligence

              </h3>

              <p className="text-slate-300 mt-2">

                Active

              </p>

            </div>

            <div className="rounded-2xl bg-white/10 p-5 border border-white/10">

              <h3 className="text-green-400 font-bold">

                ● Security Modules

              </h3>

              <p className="text-slate-300 mt-2">

                Initialized

              </p>

            </div>

          </div>

          {/* Button */}

          <button
            onClick={() => navigate("/dashboard")}
            className="mt-12 rounded-2xl bg-cyan-500 px-10 py-4 text-lg font-bold text-white transition hover:bg-cyan-400 hover:scale-105"
          >
            Enter Dashboard →
          </button>

        </div>

      </div>

    </div>
  );
}

export default Welcome;