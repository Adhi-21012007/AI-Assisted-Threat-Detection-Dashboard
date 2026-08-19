import { login } from "../../services/authService";
import { useUser } from "../../context/UserContext";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FaEye, FaEyeSlash, FaUserShield } from "react-icons/fa";
import loginVideo from "../../assets/videos/login/Blue Data Flow Animation.mp4";
import "./Login.css";

function Login() {
  const navigate = useNavigate();
  const { setUserName } = useUser();
  const [showPassword, setShowPassword] = useState(false);

  const [email, setEmail] = useState("");

  const [password, setPassword] = useState("");

  const handleLogin = async () => {

  if (!email || !password) {

    alert("Please enter Email and Password");

    return;

  }

  try {

    const user = await login(email, password);

    const name =
      user.displayName ||
      user.email?.split("@")[0] ||
      "User";
    const ADMIN_EMAIL = "srilekhamallela782@gmail.com";

const displayName =
  user.email === ADMIN_EMAIL
    ? `${name} (Admin 👑)`
    : name;

    setUserName(displayName);

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

      {/* Background Video */}

      <video
        className="background-video"
        autoPlay
        muted
        loop
        playsInline
      >
        <source src={loginVideo} type="video/mp4" />
      </video>

      {/* Overlay */}

      <div className="video-overlay"></div>

      {/* Login Card */}

      <div className="login-card">

        <div className="logo-circle">
          <FaUserShield />
        </div>

        <h1>AI-Assisted Threat Detection</h1>

        <h2>Enterprise Security Platform</h2>

        <p className="subtitle">
          Secure Login
        </p>

        {/* Email */}

        <div className="input-group">

          <label>Email Address</label>

          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

        </div>

        {/* Password */}

        <div className="input-group">

          <label>Password</label>

          <div className="password-box">

            <input
              type={showPassword ? "text" : "password"}
              placeholder="Enter your password"
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

        {/* Options */}

        <div className="options">

          <label>

            <input type="checkbox" />

            Remember Me

          </label>

          <span className="forgot">
            Forgot Password?
          </span>

        </div>

        {/* Login */}

        <button
          className="login-btn"
          onClick={handleLogin}
        >
          LOGIN
        </button>

        {/* Sign Up */}

        <button
          className="signup-btn"
          onClick={() => navigate("/signup")}
        >
          CREATE ACCOUNT
        </button>

        <div className="divider"></div>

        <p className="powered">
          Powered by
        </p>

        <div className="tech-stack">

          <span>Google Cloud</span>

          <span>Gemini AI</span>

          <span>Vertex AI</span>

        </div>

      </div>

    </div>
  );
}

export default Login;