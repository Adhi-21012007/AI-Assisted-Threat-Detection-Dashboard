Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics – Group 2
This project is an AI-assisted cybersecurity dashboard designed to help security analysts monitor, analyze, and investigate cyber threats through a centralized platform.
The system provides a dashboard for viewing detected threats, security alerts, protected assets, analytics, reports, and statistics. It also includes an AI Security Copilot that can assist users with security-related questions and threat analysis.
Main Features
Security Dashboard – Displays threat counts, protected assets, critical alerts, and security analytics.
AI Security Copilot – Provides AI-based assistance for cybersecurity-related queries.
Threat Analytics – Visualizes threat and attack information using charts.
Attack Sources – Shows the distribution of different attack categories.
Upload Center – Allows users to upload and analyze supported files/data.
Image Scan – Provides image-based security scanning.
URL Scan – Analyzes URLs for potential security risks.
QR Scan – Scans QR codes for security analysis.
Wireshark Scan – Supports analysis of network capture data.
Reports – Provides threat breakdowns, summaries, and AI recommendations.
Statistics – Displays security statistics through different visualizations.
User Profile & Settings – Provides user-specific settings and profile management.
AI Component
The AI Security Copilot uses the Groq API to process user queries. The application sends the user's prompt to the selected AI model through the Groq API and displays the generated response inside the dashboard.
Currently, your project uses:
Groq API
OpenAI GPT-OSS 120B model through Groq
Technologies
From the code you've shown, your frontend definitely uses:
React
TypeScript
Vite
Tailwind CSS
React Router
Recharts
Lucide React
PapaParse
Groq API
Git & GitHub
Vercel
For Python, Pandas, NumPy, Scikit-learn, Power BI, MITRE ATT&CK, CVE Intelligence, only list them as technologies if your team has actually implemented them in this project. Don't claim them just because they're in the suggested technology list.
Deployment
The application is deployed using Vercel, with the GitHub main branch connected for automatic deployments.
So whenever you push an updated version to main:
VS Code
   ↓
GitHub
   ↓
Vercel
   ↓
Production Deployment
Security
API keys are stored in environment variables rather than directly inside the source code.
Example:
VITE_GROQ_API_KEY=your_api_key
The .env file should remain in .gitignore and should never be uploaded to GitHub.

<<<<<<< HEAD
# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some Oxlint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
=======
# Creation of Security Operations Dashboard for Threat Detection With Risk Mitigation Analytics
>>>>>>> 15b180ebffa77de4cff0b1208fb0d9ad82cdd9d7
