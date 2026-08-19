import { useUser } from "../../context/UserContext";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FaEye,
  FaEyeSlash,
  FaUserShield,
} from "react-icons/fa";

import loginVideo from "../../assets/videos/login/Blue Data Flow Animation.mp4";
import "../Login/Login.css";

import { signup } from "../../services/authService";

function Signup() {
  const navigate = useNavigate();
  const { setUserName } = useUser();

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const handleSignup = async () => {
    if (!name || !email || !password || !confirmPassword) {
      alert("Please fill all fields");
      return;
    }

    if (password !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    try {
      const user = await signup(name, email, password);

      setUserName(user.displayName || name);

      alert("Signup Successful");

      navigate("/welcome");
    } catch (error: any) {
      console.log(error);

      alert(
        error.code + "\n\n" + error.message
      );
    }
  };

  return (
    <div className="login-page">

      <video
        className="background-video"
        autoPlay
        muted
        loop
        playsInline
      >
        <source
          src={loginVideo}
          type="video/mp4"
        />
      </video>

      <div className="video-overlay"></div>

      <div className="login-card">

        <div className="logo-circle">
          <FaUserShield />
        </div>

        <h1>Create Account</h1>

        <h2>AI-Assisted Threat Detection Dashboard</h2>

        <div className="input-group">
          <label>Full Name</label>

          <input
            type="text"
            placeholder="Enter Full Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <div className="input-group">
          <label>Email</label>

          <input
            type="email"
            placeholder="Enter Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div className="input-group">
          <label>Password</label>

          <div className="password-box">

            <input
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            <button
              type="button"
              className="eye-btn"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <FaEyeSlash /> : <FaEye />}
            </button>

          </div>
        </div>

        <div className="input-group">
          <label>Confirm Password</label>

          <div className="password-box">

            <input
              type={showConfirm ? "text" : "password"}
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) =>
                setConfirmPassword(e.target.value)
              }
            />

            <button
              type="button"
              className="eye-btn"
              onClick={() =>
                setShowConfirm(!showConfirm)
              }
            >
              {showConfirm ? (
                <FaEyeSlash />
              ) : (
                <FaEye />
              )}
            </button>

          </div>
        </div>

        <button
          className="login-btn"
          onClick={handleSignup}
        >
          CREATE ACCOUNT
        </button>

        <button
          className="signup-btn"
          onClick={() => navigate("/")}
        >
          BACK TO LOGIN
        </button>

      </div>

    </div>
  );
}

export default Signup;