# Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics Group 2

This workspace contains two Flask interfaces backed by one shared SQLite database:

- `emp_pjs` — Employee Portal on `http://127.0.0.1:5000`
- `admin_pjs` — Admin Portal on `http://127.0.0.1:5001`
- `company.db` — the shared source of truth
- `common_data.py` — schema initialization and seed data
- `security_pjs` — normalization, firewall rules, Security API, trained-model integration, and SOC data layer
- `model_pjs` — existing Random Forest + Isolation Forest inference artifacts

Run each portal in a separate terminal from the repository root:

```powershell
cd emp_pjs
pip install -r requirements.txt
python app.py
```

```powershell
cd admin_pjs
pip install -r requirements.txt
python app.py
```

Open the portals:

- Employee Portal: `http://127.0.0.1:5000`
- Admin Portal: `http://127.0.0.1:5001`
- Security Operations Center: log into the Admin Portal, then open `http://127.0.0.1:5001/security-operations/`

## How to check the Security Operations Dashboard

1. Sign in to the Employee Portal and create activity (login, attendance, a task, ticket, calendar view, or notification view).
2. Sign in to the Admin Portal and open **Security Operations** from the Admin sidebar.
3. Check **Dashboard** for database-backed KPI cards, recent events, threat trends, risk/attack distributions, and the Firewall vs AI chart.
4. Open **Security Events** and **Threat Investigation** to inspect stored model prediction, threat type, risk, confidence, reasons, timeline, and source IP.
5. In an investigation, record **Start investigation**, **Start mitigation**, **Resolve incident**, or **False positive**. Check **Risk Mitigation** and **Statistics** to see lifecycle values update.
6. Use **AI Summary**, **AI Recommendations**, and **AI Security Agent**. The agent only answers from controlled database queries; try `What happened to EMP001?` or `Which IP addresses are suspicious?`.
7. Check the API at `http://127.0.0.1:5001/api/security/health` or use the **Live API** and **REST API** SOC pages.

Run the automated checks from the repository root:

```powershell
python -m unittest security_pjs.tests.test_pipeline security_pjs.tests.test_dashboard_data security_pjs.tests.test_reconciliation_tools -v
```

Before a demo or after importing historical security records, reconcile and validate AI fields without retraining the model:

```powershell
python -m security_pjs.reconcile_ai_results company.db
python -m security_pjs.validate_security_data company.db
```

## Security intelligence extensions

The SOC now includes URL, IP, email, image-phishing, QR, VirusTotal, imported-Nmap, uploaded-PCAP/Wireshark, AI Copilot, incident correlation, and report workflows. Every saved analysis becomes a normalized shared `security_events` record with an explainable risk score and, for significant correlated signals, a linked incident. It can then be investigated, mitigated, resolved, or marked **FALSE POSITIVE** using the existing lifecycle.

- **URL/IP/email** analysis is local and explainable. A VirusTotal result appears only when `VIRUSTOTAL_API_KEY` is set; otherwise the page explicitly reports that external intelligence is unavailable.
- **Image OCR**, **QR decoding**, and **PCAP parsing** are optional/local. Unsupported files and unavailable optional libraries return an honest unavailable state; uploaded source files are not modified or executed.
- **Nmap** accepts only analyst-uploaded, authorised Nmap XML output. The application never starts an arbitrary target scan.
- **AI Security Copilot** falls back to the controlled database-grounded Security Agent unless a `GROQ_API_KEY` is configured. It is advisory and cannot replace deterministic detection results.
- **Vulnerability** and **pentest** records support lifecycle states and are linked into the same event flow as manual, authorised evidence—not represented as live scans.

Configure optional keys in deployment secrets or local environment variables, never in source code. See [deploy/.env.example](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/deploy/.env.example).

To use the separate UNSW-NB15 network-traffic research model with an approved labelled CSV, see [model_pjs/network_ml/README.md](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/model_pjs/network_ml/README.md). It is deliberately kept separate from the existing employee-behaviour Random Forest and Isolation Forest; no network-model result is claimed until an actual dataset has been supplied and trained.

Run the full checks after changes:

```powershell
python -m unittest security_pjs.tests.test_pipeline security_pjs.tests.test_dashboard_data security_pjs.tests.test_reconciliation_tools security_pjs.tests.test_intelligence -v
```

## GCP readiness

Cloud Run container definitions, Cloud Build configuration, Cloud Run service manifests, Secret Manager environment references, and an environment template are in [deploy](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/deploy). Follow [GCP_DEPLOYMENT.md](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/deploy/GCP_DEPLOYMENT.md) before deployment.

The provided Cloud Run files support a short-lived single-instance demo only because SQLite is not durable across Cloud Run instances. A production GCP rollout requires Cloud SQL migration; this limitation is deliberately documented rather than hidden.

Default accounts:

- Admin: `admin` / `admin@123`
- Employee: `EMP001` / `employee123`

Admin-created employees, teams, attendance corrections, assigned tasks, calendar events, notifications, ticket changes, and all activity records are immediately available in the Employee Portal. Employee attendance, tasks, tickets, and activity records are immediately visible in the Admin Portal.

The older `database.db` files inside the project folders are not used; both application configurations point exclusively to `company.db`.
