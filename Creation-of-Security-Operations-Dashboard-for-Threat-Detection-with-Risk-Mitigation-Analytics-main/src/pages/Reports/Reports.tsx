import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import Header from "../../components/Layout/Header/Header";

import ReportSummary from "./ReportSummary";
import ThreatBreakdown from "./ThreatBreakdown";
import AIRecommendations from "./AIRecommendations";
import RecentReports from "./RecentReports";

function Reports() {

  return (

    <div className="min-h-screen overflow-x-hidden bg-[#080D18]">

      <Sidebar />

      <div
        className="relative transition-all duration-500"
        style={{
          marginLeft: "88px",
        }}
      >

        <Header />

        <main
          className="relative mx-auto max-w-[1500px] px-14 py-12"
          style={{
            paddingRight: "120px",
          }}
        >

          <div className="mb-10">

            <h1 className="text-5xl font-bold text-white">

              Enterprise Security Reports

            </h1>

            <p className="mt-3 text-lg text-slate-400">

              AI Generated Security Reports powered by Firebase & Gemini AI

            </p>

          </div>

          <ReportSummary />

          <div className="mt-10 grid grid-cols-1 gap-8 xl:grid-cols-2">

            <ThreatBreakdown />

            <AIRecommendations />

          </div>

          <div className="mt-10">

            <RecentReports />

          </div>

        </main>

      </div>

    </div>

  );

}

export default Reports;