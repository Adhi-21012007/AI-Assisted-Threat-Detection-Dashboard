"""Small, configurable, explainable rules for the prototype firewall simulator."""
from datetime import datetime, timedelta, timezone
from . import config

def _alert(event, alert_type, severity, score, description, rule, action):
    return {"alert_type":alert_type,"severity":severity,"risk_score":score,"description":description,"triggered_rule":rule,"recommended_action":action}

def evaluate(event, recent_events, historical_events, settings=None):
    alerts=[]; now=datetime.fromisoformat(event["timestamp"])
    settings=settings or {};suspicious=settings.get('failed_login_suspicious',config.FAILED_LOGIN_SUSPICIOUS);critical=settings.get('failed_login_critical',config.FAILED_LOGIN_CRITICAL);login_window=settings.get('failed_login_window_minutes',config.FAILED_LOGIN_WINDOW_MINUTES);download_threshold=settings.get('download_threshold',config.DOWNLOAD_THRESHOLD);workday_start=settings.get('workday_start',config.WORKDAY_START);workday_end=settings.get('workday_end',config.WORKDAY_END)
    failed=[x for x in recent_events if x["event_type"]=="LOGIN_FAILED" and x.get("employee_id")==event.get("employee_id")]
    if event["event_type"]=="LOGIN_FAILED":
        count=len(failed)
        if count>=critical: alerts.append(_alert(event,"BRUTE_FORCE","CRITICAL",95,f"{count} failed logins within {login_window} minutes","FAILED_LOGIN_CRITICAL","Block or rate-limit the source and investigate the account."))
        elif count>=suspicious: alerts.append(_alert(event,"SUSPICIOUS_LOGIN","MEDIUM",55,f"{count} failed logins within {login_window} minutes","FAILED_LOGIN_THRESHOLD","Review authentication activity and source IP."))
    if event["event_type"]=="LOGIN_SUCCESS" and event.get("ip_address"):
        known={x.get("ip_address") for x in historical_events if x.get("event_id") != event.get("event_id") and x["event_type"]=="LOGIN_SUCCESS" and x.get("employee_id")==event.get("employee_id") and x.get("ip_address")}
        if known and event["ip_address"] not in known: alerts.append(_alert(event,"SUSPICIOUS_LOGIN","MEDIUM",50,"Successful login from a new IP address","NEW_IP_LOGIN","Confirm the user and monitor the new source IP."))
    if event["event_type"] in {"LOGIN_SUCCESS","LOGIN_FAILED"}:
        hour=now.hour
        if hour<workday_start or hour>=workday_end: alerts.append(_alert(event,"UNUSUAL_LOGIN_TIME","LOW",35,"Login activity occurred outside configured working hours","UNUSUAL_LOGIN_TIME","Review context before escalating."))
    downloads=[x for x in recent_events if x["event_type"]=="FILE_DOWNLOAD" and x.get("employee_id")==event.get("employee_id")]
    download_count=sum(int((x.get("metadata") or {}).get("download_count",1)) for x in downloads)
    if event["event_type"]=="FILE_DOWNLOAD" and download_count>=download_threshold: alerts.append(_alert(event,"POSSIBLE_DATA_EXFILTRATION","HIGH",80,f"{download_count} downloads within {settings.get('download_window_minutes',config.DOWNLOAD_WINDOW_MINUTES)} minutes","EXCESSIVE_DOWNLOADS","Review accessed files and consider restricting downloads."))
    metadata=event.get("metadata") or {}
    if metadata.get("sensitive") or event["event_type"]=="SENSITIVE_FILE_ACCESS": alerts.append(_alert(event,"SENSITIVE_FILE_ACCESS","MEDIUM",60,"Sensitive resource access was recorded","SENSITIVE_FILE_ACCESS","Validate business need and audit access."))
    if event["event_type"]=="PRIVILEGE_CHANGE" or metadata.get("privilege_change"): alerts.append(_alert(event,"PRIVILEGE_CHANGE","HIGH",75,"Privilege or role change was recorded","PRIVILEGE_CHANGE","Verify authorisation and review the changed permissions."))
    if len(historical_events)>=20:
        current_window=len([x for x in recent_events if x.get("employee_id")==event.get("employee_id")])
        hourly_baseline=max(1, len(historical_events)/(30*24))
        if current_window > max(10, hourly_baseline*5):
            alerts.append(_alert(event,"ACTIVITY_SPIKE","MEDIUM",50,"Activity volume exceeded the recent user baseline","ACTIVITY_SPIKE","Review the sequence of actions for automation or misuse."))
    return alerts
