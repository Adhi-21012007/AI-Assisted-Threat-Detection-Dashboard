import { useEffect } from "react";
import { Routes, Route } from "react-router-dom";

import { updateLiveData } from "./services/liveData";

import ProtectedRoute from "./components/ProtectedRoute";

import NmapScan from "./pages/NmapScan/NmapScan";

import PenetrationTesting from "./pages/PenetrationTesting/PenetrationTesting";

import TestGemini from "./pages/TestGemini/TestGemini";
import Login from "./pages/Login/Login";
import Signup from "./pages/Signup/Signup";
import Welcome from "./pages/Welcome/Welcome";
import Dashboard from "./pages/Dashboard/Dashboard";
import Analytics from "./pages/Analytics/Analytics";
import UploadCenter from "./pages/UploadCenter/UploadCenter";
import AIAgent from "./pages/AIAgent/AIAgent";
import Reports from "./pages/Reports/Reports";
import Settings from "./pages/Settings/Settings";
import Profile from "./pages/Profile/Profile";
import ImageScan from "./pages/ImageScan/ImageScan";
import EmailScan from "./pages/EmailScan/EmailScan";
import QRScan from "./pages/QRScan/QRScan";
import URLScan from "./pages/URLScan/URLScan";
import IPScan from "./pages/IPScan/IPScan";
import Statistics from "./pages/Statistics/Statistics";
import WiresharkScan from "./pages/WiresharkScan/WiresharkScan";

function App() {

  useEffect(() => {

    updateLiveData();

    const timer = setInterval(() => {

      updateLiveData();

    }, 5000);

    return () => clearInterval(timer);

  }, []);

  return (

    <Routes>

      {/* Public Routes */}

      <Route path="/" element={<Login />} />

      <Route path="/signup" element={<Signup />} />

      <Route path="/welcome" element={<Welcome />} />

      <Route path="/testgemini" element={<TestGemini />} />

      {/* Protected Routes */}

      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />

      <Route
        path="/analytics"
        element={
          <ProtectedRoute>
            <Analytics />
          </ProtectedRoute>
        }
      />

      <Route
        path="/statistics"
        element={
          <ProtectedRoute>
            <Statistics />
          </ProtectedRoute>
        }
      />

      <Route
        path="/upload"
        element={
          <ProtectedRoute>
            <UploadCenter />
          </ProtectedRoute>
        }
      />

      <Route
        path="/agent"
        element={
          <ProtectedRoute>
            <AIAgent />
          </ProtectedRoute>
        }
      />
      <Route
        path="/wireshark"
        element={
          <ProtectedRoute>
            <WiresharkScan />
          </ProtectedRoute>
        }
      />

      <Route
        path="/reports"
        element={
          <ProtectedRoute>
            <Reports />
          </ProtectedRoute>
        }
      />

      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <Profile />
          </ProtectedRoute>
        }
      />

      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        }
      />

      <Route
        path="/emailscan"
        element={
          <ProtectedRoute>
            <EmailScan />
          </ProtectedRoute>
        }
      />

      <Route
        path="/urlscan"
        element={
          <ProtectedRoute>
            <URLScan />
          </ProtectedRoute>
        }
      />

      <Route
        path="/ipscan"
        element={
          <ProtectedRoute>
            <IPScan />
          </ProtectedRoute>
        }
      />

      <Route
        path="/qrscan"
        element={
          <ProtectedRoute>
            <QRScan />
          </ProtectedRoute>
        }
      />
      <Route
        path="/nmapscan"
        element={
          <ProtectedRoute>
          <NmapScan />
          </ProtectedRoute>
        }
       />
      <Route
        path="/pentest"
        element={
          <ProtectedRoute>
          <PenetrationTesting />
          </ProtectedRoute>
        }
       />

      <Route
        path="/imagescan"
        element={
          <ProtectedRoute>
            <ImageScan />
          </ProtectedRoute>
        }
      />

    </Routes>

  );

}

export default App;