import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import Header from "../../components/Layout/Header/Header";

import { logout } from "../../services/authService";

import { useNavigate } from "react-router-dom";
import { useState } from "react";

import {
  FaBell,
  FaSyncAlt,
  FaRobot,
  FaSignOutAlt,
  FaCog,
} from "react-icons/fa";

function Settings() {

  const navigate = useNavigate();

  const [notifications, setNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [aiSuggestions, setAiSuggestions] = useState(true);

  const handleSignOut = async () => {

    await logout();

    navigate("/");

  };

  return (

    <div className="min-h-screen overflow-x-hidden bg-[#080D18]">

      <Sidebar />

      <div
        className="relative transition-all duration-500"
        style={{ marginLeft: "88px" }}
      >

        <Header />

        <main
          className="mx-auto max-w-[1500px] px-14 py-12"
          style={{ paddingRight: "120px" }}
        >

          <h1 className="text-5xl font-bold text-white">
            Settings
          </h1>

          <p className="mt-3 text-lg text-slate-400">
            Configure your AI Threat Detection Dashboard
          </p>

          <div className="mt-10 space-y-6">

            {/* Notifications */}

            <div className="flex items-center justify-between rounded-2xl bg-[#111827] p-6 border border-cyan-500/20">

              <div className="flex items-center gap-4">

                <FaBell className="text-cyan-400 text-2xl"/>

                <div>

                  <h2 className="text-white text-xl font-semibold">
                    Notifications
                  </h2>

                  <p className="text-slate-400">
                    Receive security alerts
                  </p>

                </div>

              </div>

              <input
                type="checkbox"
                checked={notifications}
                onChange={() => setNotifications(!notifications)}
              />

            </div>

            {/* Auto Refresh */}

            <div className="flex items-center justify-between rounded-2xl bg-[#111827] p-6 border border-cyan-500/20">

              <div className="flex items-center gap-4">

                <FaSyncAlt className="text-cyan-400 text-2xl"/>

                <div>

                  <h2 className="text-white text-xl font-semibold">
                    Auto Refresh
                  </h2>

                  <p className="text-slate-400">
                    Refresh dashboard every minute
                  </p>

                </div>

              </div>

              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={() => setAutoRefresh(!autoRefresh)}
              />

            </div>

            {/* AI Suggestions */}

            <div className="flex items-center justify-between rounded-2xl bg-[#111827] p-6 border border-cyan-500/20">

              <div className="flex items-center gap-4">

                <FaRobot className="text-cyan-400 text-2xl"/>

                <div>

                  <h2 className="text-white text-xl font-semibold">
                    AI Recommendations
                  </h2>

                  <p className="text-slate-400">
                    Enable Gemini AI suggestions
                  </p>

                </div>

              </div>

              <input
                type="checkbox"
                checked={aiSuggestions}
                onChange={() => setAiSuggestions(!aiSuggestions)}
              />

            </div>

            {/* Danger Zone */}

            <div className="mt-12 rounded-2xl border border-red-600 bg-[#1B1113] p-8">

              <div className="flex items-center gap-3">

                <FaCog className="text-red-500 text-2xl"/>

                <h2 className="text-3xl font-bold text-red-400">
                  Danger Zone
                </h2>

              </div>

              <p className="mt-3 text-slate-400">
                Signing out will end your current session and return you to the login page.
              </p>

              <button
                onClick={handleSignOut}
                className="mt-8 flex items-center gap-3 rounded-xl bg-red-600 px-8 py-4 text-lg font-semibold text-white transition hover:bg-red-700"
              >

                <FaSignOutAlt />

                Sign Out

              </button>

            </div>

          </div>

        </main>

      </div>

    </div>

  );

}

export default Settings;