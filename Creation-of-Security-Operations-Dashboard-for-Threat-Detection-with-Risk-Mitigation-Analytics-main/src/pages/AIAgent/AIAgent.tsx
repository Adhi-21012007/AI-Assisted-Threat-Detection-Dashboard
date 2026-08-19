import {
  useState,
} from "react";

import Header from "../../components/Layout/Header/Header";
import Sidebar from "../../components/Layout/Sidebar/Sidebar";

import {
  Sparkles,
  Send,
  Mic,
} from "lucide-react";

import { askGemini } from "../../services/gemini";

import aiVideo from "../../assets/videos/ai/ai-assistant.mp4";
import bgVideo from "../../assets/videos/loading/Server Room Animation.mp4";

import { useUser } from "../../context/UserContext";

function AIAgent() {

  const { userName } = useUser();

  const [started, setStarted] = useState(false);

  const [message, setMessage] = useState("");

  const [listening, setListening] = useState(false);

  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: `Hello ${userName} 👋 Welcome to Enterprise AI Security Copilot.`,
    },
  ]);

  /* ================= VOICE RECOGNITION ================= */

  const startListening = () => {

    const SpeechRecognition =
      (window as any).SpeechRecognition ||
      (window as any).webkitSpeechRecognition;

    if (!SpeechRecognition) {

      alert("Speech Recognition is not supported in this browser.");

      return;

    }

    const recognition = new SpeechRecognition();

    recognition.lang = "en-US";

    recognition.interimResults = false;

    recognition.maxAlternatives = 1;

    recognition.start();

    setListening(true);

    recognition.onresult = (event: any) => {

      const transcript = event.results[0][0].transcript;

      setMessage(transcript);

      setListening(false);

    };

    recognition.onerror = () => {

      setListening(false);

    };

    recognition.onend = () => {

      setListening(false);

    };

  };

  /* ================= SEND MESSAGE ================= */

  const handleSend = async () => {

    if (!message.trim()) return;

    const userMessage = message;

    setStarted(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "user",
        text: userMessage,
      },
    ]);

    setMessage("");

    try {

      const aiReply = await askGemini(userMessage);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: aiReply,
        },
      ]);

    } catch {

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: "Sorry, I couldn't generate a response.",
        },
      ]);

    }

  };

  return (<div className="relative min-h-screen overflow-hidden bg-[#070B16]">

  {/* Background Video */}

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

  {/* Overlay */}

  <div className="fixed inset-0 bg-[#050913]/30 backdrop-blur-[1px]" />

  {/* Header */}

  <Header />

  {/* Sidebar */}

  <Sidebar />

  {/* Main */}

  <div
    className="relative transition-all duration-500"
    style={{
      marginLeft: "88px",
    }}
  >

    <main className="mx-auto max-w-[1700px] px-12 py-10">

      <div className="mb-8">

        <h1 className="text-5xl font-bold text-white">

          AI Security Copilot

        </h1>

        <p className="mt-4 text-lg text-slate-300">

          Enterprise AI assistant for malware analysis,
          phishing detection,
          cloud security,
          SIEM logs and cyber threat intelligence.

        </p>

      </div>

      {!started && (

        <div className="rounded-[32px] border border-[#26324A] bg-[#101827]/90 shadow-2xl backdrop-blur-xl">

          <div className="flex flex-col items-center px-12 py-12">

            <video
              autoPlay
              muted
              loop
              playsInline
              className="h-[320px] w-[650px] rounded-3xl object-cover"
            >

              <source
                src={aiVideo}
                type="video/mp4"
              />

            </video>

            <div className="mt-10 text-center">

              <h2 className="text-5xl font-bold text-white">

                Hello,

                <span className="ml-2 bg-gradient-to-r from-cyan-400 via-blue-400 to-violet-500 bg-clip-text text-transparent">

                  {userName}

                </span>

                👋

              </h2>

              <p className="mx-auto mt-6 max-w-5xl text-xl leading-10 text-slate-300">

                Welcome to Enterprise AI Security Copilot.

                Ask anything about malware,
                phishing attacks,
                cyber threats,
                cloud security,
                vulnerability assessment,
                SIEM logs,
                incident response,
                digital forensics,
                penetration testing,
                reports and enterprise security.

              </p>

            </div>

            <div className="mt-10 flex flex-wrap justify-center gap-4">

              <button className="rounded-full bg-violet-600/20 px-6 py-3 text-violet-300 hover:bg-violet-600/30">

                Today's Threats

              </button>

              <button className="rounded-full bg-cyan-500/20 px-6 py-3 text-cyan-300 hover:bg-cyan-500/30">

                Analyze Logs

              </button>

              <button className="rounded-full bg-green-500/20 px-6 py-3 text-green-300 hover:bg-green-500/30">

                Generate Report

              </button>

              <button className="rounded-full bg-orange-500/20 px-6 py-3 text-orange-300 hover:bg-orange-500/30">

                Explain Malware

              </button>

            </div>

            <div className="mt-12 flex w-full max-w-5xl items-center gap-4 rounded-2xl border border-[#2B3550] bg-[#1B233A] p-4">

              <Sparkles
                size={22}
                className="text-cyan-400"
              />

              <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    handleSend();
                  }
                }}
                placeholder="Ask Enterprise AI Security Copilot..."
                className="flex-1 bg-transparent text-lg text-white placeholder:text-slate-500 outline-none"
              />

              {/* 🎤 Microphone */}

              <button
                onClick={startListening}
                className={`flex h-14 w-14 items-center justify-center rounded-xl transition ${
                  listening
                    ? "bg-red-500 animate-pulse"
                    : "bg-violet-600 hover:bg-violet-500"
                }`}
              >

                <Mic
                  size={22}
                  className="text-white"
                />

              </button>

              {/* Send */}

              <button
                onClick={handleSend}
                className="flex h-14 w-14 items-center justify-center rounded-xl bg-cyan-500 transition hover:bg-cyan-400"
              >

                <Send
                  size={22}
                  className="text-white"
                />

              </button>

            </div>

          </div>

        </div>

      )}
            {started && (

        <div className="rounded-[32px] border border-[#26324A] bg-[#101827]/90 shadow-2xl backdrop-blur-xl">

          <div className="flex h-[75vh] flex-col">

            {/* Messages */}

            <div className="flex-1 overflow-y-auto space-y-6 p-8">

              {messages.map((msg, index) => (

                <div
                  key={index}
                  className={`flex ${
                    msg.role === "user"
                      ? "justify-end"
                      : "justify-start"
                  }`}
                >

                  <div
                    className={`max-w-[70%] rounded-2xl px-6 py-4 ${
                      msg.role === "user"
                        ? "bg-cyan-500 text-white"
                        : "bg-[#1B233A] text-white"
                    }`}
                  >

                    {msg.text}

                  </div>

                </div>

              ))}

            </div>

            {/* Input */}

            <div className="border-t border-[#26324A] p-6">

              <div className="flex items-center gap-4 rounded-2xl bg-[#1B233A] p-4">

                <input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      handleSend();
                    }
                  }}
                  placeholder="Ask Enterprise AI Security Copilot..."
                  className="flex-1 bg-transparent text-white outline-none"
                />

                {/* 🎤 Microphone */}

                <button
                  onClick={startListening}
                  className={`flex h-12 w-12 items-center justify-center rounded-xl transition ${
                    listening
                      ? "bg-red-500 animate-pulse"
                      : "bg-violet-600 hover:bg-violet-500"
                  }`}
                >

                  <Mic
                    size={20}
                    className="text-white"
                  />

                </button>

                {/* Send */}

                <button
                  onClick={handleSend}
                  className="rounded-xl bg-cyan-500 px-5 py-3 text-white transition hover:bg-cyan-400"
                >

                  <Send
                    size={20}
                  />

                </button>

              </div>

            </div>

          </div>

        </div>

      )}
          </main>

  </div>

</div>

);

}

export default AIAgent;
      