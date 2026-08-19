# Security Pipeline + Firewall + API

`security_pjs` connects portal activity logs to the existing firewall and trained model:

`activity_logs → normalizer → rule-based firewall simulator → existing model_pjs inference → security_events → API`

It uses the existing root `company.db`; no additional application database or ML training is created. The Employee Portal calls `process_activity_log()` immediately after each activity-log insert. A stable `activity-{activity_log_id}` event ID prevents duplicate event processing.

## AI integration

`ai_adapter.py` converts a normalized event into the live feature structure expected by `model_pjs.detection.predict_activity`. It derives deterministic values from the employee profile and prior `security_events`; telemetry not present in the portal event is explicitly retained in `ai_feature_context.metadata_unavailable` while the model's own safe defaults are used.

The existing Random Forest and Isolation Forest artifacts provide the prediction, threat type, confidence, risk score, severity, anomaly signal, and reasons. The adapter only supplies a contextual recommended action. AI fields are stored on the associated `EVENT` record (`ai_prediction`, `ai_threat_type`, `ai_confidence`, `ai_anomaly_detected`, `ai_reasons_json`, `ai_recommended_action`, `ai_processed_at`, `ai_status`, and `ai_feature_context_json`). If inference fails, the source event and any firewall alert remain intact and `ai_status` is set to `FAILED` for a later retry.

## API

The API is registered on the Admin Portal server (`http://127.0.0.1:5001`):

- `POST /api/security/events`
- `POST /api/security/alerts`
- `GET /api/security/events`
- `GET /api/security/alerts`
- `GET /api/security/health`

Example:

```powershell
Invoke-RestMethod -Method Post -ContentType 'application/json' `
  -Uri http://127.0.0.1:5001/api/security/events `
  -Body '{"employee_id":"EMP001","event_type":"LOGIN_FAILED","timestamp":"2026-08-14T20:30:00","status":"FAILED","source":"employee_portal","metadata":{"attempt":8}}'
```

Rules and thresholds are configurable with `SECURITY_*` environment variables in `config.py`. The rules detect failed-login patterns, new IP logins, after-hours logins, downloads, sensitive access, privilege changes, and sufficiently supported activity spikes. Duplicate alerts are suppressed per employee/alert type/window. The firewall and AI remain separate: firewall rules produce deterministic alerts; the model adds behavioural classification to every stored event.

Run tests from the repository root:

```powershell
python -m unittest security_pjs.tests.test_pipeline -v
```

This module is an application-level security simulator, not a real network firewall. It is structured so model inference can move to an asynchronous worker in a future deployment phase.
