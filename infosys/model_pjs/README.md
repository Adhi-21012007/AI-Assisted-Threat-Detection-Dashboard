# ML Threat Detection Model

This package is a local, hybrid threat-detection component for the Northstar Employee and Admin portals. It learns from aggregated behavioural windows using a Random Forest classifier (Normal, Suspicious, Threat) plus an Isolation Forest anomaly detector. It is not an LLM or an external API.

## Quick start

```powershell
pip install -r requirements.txt
python run_workflow.py
```

The workflow generates 30,000 reproducible synthetic records, trains and evaluates both models, runs manual tests, saves plots under `outputs/`, and creates `final_threat_detection_model.zip`.

## Inference

```python
from detection.predict import predict_activity

event = predict_activity({
    "user_id": "EMP001", "user_role": "Employee",
    "department": "Technology", "team": "Product Engineering",
    "hour": 2, "login_count": 35, "failed_login_count": 28,
    "unique_ip_count": 4, "new_ip_indicator": 1,
    "activity_spike": 1, "activities_per_hour": 55
})
print(event)
```

The result has `prediction`, `threat_type`, `confidence`, `risk_score`, `severity`, supporting reasons, timestamps, and source metadata.

## Risk scoring

The 0–100 score begins with the trained classifier's class and confidence. Bounded modifiers add evidence from failed logins, download volume, Isolation Forest anomaly status, new IPs, and privilege changes. Low is 0–30, Medium 31–70, High 71–90, and Critical 91–100.

Threat types are explanatory classifications inferred only after the ML prediction. When the available features cannot support a specific type, the output remains `Suspicious Behaviour` or `Abnormal Behaviour`.

## Integration

`data_source/activity_provider.py` defines a database-neutral `ActivityProvider` interface. `SQLiteActivityProvider` reads the existing root `company.db` activity log for development; a Firebase, REST, SIEM, firewall, EDR, or queue provider can implement the same method later. Keep a `ThreatPredictor` loaded in the future service and call `predict_activity` for each aggregated activity window—do not retrain for every event.

For `emp_pjs`, forward new employee activity logs to the provider after they are committed. For `admin_pjs`, persist returned security events into the existing `security_events` table for dashboard display. Production integrations should introduce an authenticated API/data layer rather than importing the model inside request handlers.

## Limitations

The training data is realistic synthetic data, not production telemetry. Its metrics are development indicators only and cannot demonstrate live security efficacy. Validate thresholds, performance, fairness, false positives, adversarial robustness, data governance, and analyst workflows against reviewed real logs before operational use.
