import Sidebar from "../../components/Layout/Sidebar/Sidebar";
import Header from "../../components/Layout/Header/Header";

import { auth } from "../../firebase";
import { logout } from "../../services/authService";

import { useNavigate } from "react-router-dom";

import {
  FaUserCircle,
  FaEnvelope,
  FaIdBadge,
  FaShieldAlt,
  FaSignOutAlt,
} from "react-icons/fa";

function Profile() {

  const navigate = useNavigate();

  const user = auth.currentUser;

  const handleLogout = async () => {

    await logout();

    navigate("/");

  };

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
          className="mx-auto max-w-[1500px] px-14 py-12"
          style={{
            paddingRight: "120px",
          }}
        >

          <h1 className="text-5xl font-bold text-white">
            My Profile
          </h1>

          <p className="mt-3 text-lg text-slate-400">
            Firebase Authenticated User Information
          </p>

          <div className="mt-10 rounded-3xl border border-cyan-500/20 bg-[#111827] p-10 shadow-xl">

            <div className="flex items-center gap-6">

              <FaUserCircle
                className="text-cyan-400"
                size={90}
              />

              <div>

                <h2 className="text-3xl font-bold text-white">

                  {user?.displayName || "User"}

                </h2>

                <p className="text-slate-400">

                  Security Analyst

                </p>

              </div>

            </div>

            <div className="mt-10 grid gap-6 md:grid-cols-2">

              <div className="rounded-xl bg-[#1E293B] p-5">

                <div className="flex items-center gap-3 text-cyan-400">

                  <FaEnvelope />

                  <span>Email</span>

                </div>

                <p className="mt-2 text-white">

                  {user?.email}

                </p>

              </div>

              <div className="rounded-xl bg-[#1E293B] p-5">

                <div className="flex items-center gap-3 text-cyan-400">

                  <FaIdBadge />

                  <span>User ID</span>

                </div>

                <p className="mt-2 break-all text-white">

                  {user?.uid}

                </p>

              </div>

              <div className="rounded-xl bg-[#1E293B] p-5">

                <div className="flex items-center gap-3 text-cyan-400">

                  <FaShieldAlt />

                  <span>Email Verified</span>

                </div>

                <p className="mt-2 text-white">

                  {user?.emailVerified ? "Verified ✅" : "Not Verified"}

                </p>

              </div>

              <div className="rounded-xl bg-[#1E293B] p-5">

                <div className="flex items-center gap-3 text-cyan-400">

                  <FaShieldAlt />

                  <span>Account Status</span>

                </div>

                <p className="mt-2 text-green-400">

                  Active

                </p>

              </div>

            </div>

            <button

              onClick={handleLogout}

              className="mt-10 flex items-center gap-3 rounded-xl bg-red-600 px-8 py-4 text-lg font-semibold text-white transition hover:bg-red-700"

            >

              <FaSignOutAlt />

              Logout

            </button>

          </div>

        </main>

      </div>

    </div>

  );

}

export default Profile;