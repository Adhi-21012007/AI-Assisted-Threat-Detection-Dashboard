# GCP deployment readiness

This project now has two Cloud Run container definitions: Employee Portal and Admin/Security Operations. Local development remains unchanged and continues to use the shared `company.db` file.

## Important database limitation

SQLite at `/tmp/company.db` is ephemeral in Cloud Run. The supplied manifests set `maxScale: "1"` only for a short-lived demonstration deployment. It is **not** a durable or multi-instance production database.

Before production deployment, migrate the SQLite data access layer to Cloud SQL (PostgreSQL or MySQL), keep schema migrations under version control, and inject the Cloud SQL connection through Secret Manager/Cloud SQL connector. Do not point multiple Cloud Run instances at a shared SQLite file.

## Build images

From the repository root, after setting your GCP project values:

```powershell
gcloud builds submit --config deploy/cloudbuild.yaml --substitutions=_REGION=REGION,_REPOSITORY=infosys
```

Or build locally for a smoke test:

```powershell
docker build -f Dockerfile.employee -t employee-portal .
docker build -f Dockerfile.admin -t security-operations-admin .
docker run --rm -p 8080:8080 -e APP_ENV=production -e SECRET_KEY=replace-with-a-long-random-secret employee-portal
```

## Cloud Run prerequisites

1. Create Artifact Registry repository `infosys`.
2. Store independent random portal secrets and `SECURITY_API_KEY` in Secret Manager.
3. Replace `PROJECT_ID`, `REGION`, `TAG` in the two service manifests.
4. Deploy the Employee and Admin services separately. Use an identity-aware proxy or Cloud Run IAM for the Admin service.
5. Keep `SECURITY_API_KEY` only in Secret Manager. External event clients must send it in `X-API-Key`; it is not required locally when the environment variable is unset.

## Cloud Run demo deployment

```powershell
gcloud run services replace deploy/cloudrun/employee-service.yaml --region REGION
gcloud run services replace deploy/cloudrun/admin-service.yaml --region REGION
```

## Production target

Cloud Run services → API Gateway/IAM → Pub/Sub queue → model worker → Cloud SQL → BigQuery export. Cloud Storage should hold attachments/static imports, and Secret Manager should hold all runtime secrets.

## Required production services and controls

- Enable Cloud Run, Cloud Build, Artifact Registry, Secret Manager, Cloud SQL Admin, Pub/Sub, Cloud Storage, BigQuery, Cloud Logging, and Cloud Monitoring APIs.
- Grant the Cloud Run service account only Secret Manager accessor, Pub/Sub publisher/subscriber as applicable, Cloud SQL Client, Storage object access to its bucket, and BigQuery data-editor/export permissions.
- Use Cloud Run `/api/security/health` for the Security API health probe. Production portal health checks should be routed through authenticated infrastructure rather than exposing administrative pages.
- Retain Cloud Build image tags for rollback and redeploy a previous immutable image tag if needed.
- Set budgets/alerts before enabling Cloud SQL, BigQuery exports, or public Cloud Run ingress.
