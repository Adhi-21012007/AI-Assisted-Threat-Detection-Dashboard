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

External threat intelligence, SIEM, GCP, vulnerability scanners, and penetration-testing scanners remain explicitly **Not Connected**. Their SOC pages do not fabricate external findings.

## GCP readiness

Cloud Run container definitions, Cloud Build configuration, Cloud Run service manifests, Secret Manager environment references, and an environment template are in [deploy](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/deploy). Follow [GCP_DEPLOYMENT.md](C:/Users/keesh/OneDrive/ドキュメント/ChatGPT/infosys/deploy/GCP_DEPLOYMENT.md) before deployment.

The provided Cloud Run files support a short-lived single-instance demo only because SQLite is not durable across Cloud Run instances. A production GCP rollout requires Cloud SQL migration; this limitation is deliberately documented rather than hidden.

Default accounts:

- Admin: `admin` / `admin@123`
- Employee: `EMP001` / `employee123`

Admin-created employees, teams, attendance corrections, assigned tasks, calendar events, notifications, ticket changes, and all activity records are immediately available in the Employee Portal. Employee attendance, tasks, tickets, and activity records are immediately visible in the Admin Portal.

The older `database.db` files inside the project folders are not used; both application configurations point exclusively to `company.db`.
