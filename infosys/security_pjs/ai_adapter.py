"""Bridge normalized security events to the existing model_pjs inference package."""
from datetime import datetime, timedelta, timezone
import logging, sqlite3, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from model_pjs.detection.predict import predict_activity

logger=logging.getLogger("security_ai")

def _parse(value):
    return datetime.fromisoformat(str(value).replace("Z","+00:00"))
def _events(connection, employee_id, since):
    return connection.execute("SELECT * FROM security_events WHERE record_type='EVENT' AND employee_id=? AND timestamp>=? ORDER BY timestamp",(employee_id,since.isoformat())).fetchall()
def _recommend(result):
    threat=result.get("threat_type","");severity=result.get("severity","")
    if threat=="Brute Force Attack":return "Temporarily lock or rate-limit the account and investigate source IP activity."
    if threat=="Possible Data Exfiltration":return "Review file transfers, restrict downloads if needed, and validate business purpose."
    if threat=="Privilege Abuse":return "Validate authorisation and review changed permissions immediately."
    if severity in {"High","Critical"}:return "Escalate to security operations and investigate the activity sequence."
    if result.get("prediction")=="Suspicious":return "Review the activity context and monitor subsequent events."
    return "No immediate action; retain the event for normal monitoring."

def event_to_features(connection,event):
    """Build model input from observed history; absent telemetry stays at model defaults."""
    employee_id=event.get("employee_id");now=_parse(event["timestamp"]);metadata=event.get("metadata") or {}
    profile=connection.execute("""SELECT e.*,t.name team_name FROM employees e LEFT JOIN teams t ON t.id=e.team_id WHERE e.employee_id=?""",(employee_id,)).fetchone()
    profile=dict(profile) if profile else {}
    hour_events=_events(connection,employee_id,now-timedelta(hours=1));day_events=_events(connection,employee_id,now-timedelta(days=1));month_events=_events(connection,employee_id,now-timedelta(days=30));auth=[x for x in hour_events if x["event_type"] in {"LOGIN_SUCCESS","LOGIN_FAILED"}]
    failed=sum(x["event_type"]=="LOGIN_FAILED" for x in auth);ips={x["ip_address"] for x in day_events if x["ip_address"]};downloads=sum(int(__import__('json').loads(x["metadata_json"] or '{}').get("download_count",1)) for x in hour_events if x["event_type"]=="FILE_DOWNLOAD")
    known_ips={x["ip_address"] for x in month_events if x["event_id"]!=event.get("event_id") and x["event_type"]=="LOGIN_SUCCESS" and x["ip_address"]}
    try: age=max(0,(now.date()-datetime.fromisoformat(profile.get("joining_date") or now.date().isoformat()).date()).days)
    except ValueError:age=365
    baseline=max(1,len(month_events)/720);spike=int(len(hour_events)>max(10,baseline*5))
    unavailable=[name for name in ["session_duration","file_upload_count","sensitive_file_access"] if name not in metadata]
    new_ip=bool(event.get("ip_address") and known_ips and event["ip_address"] not in known_ips)
    return {"user_id":employee_id,"user_role":"Admin" if metadata.get("user_type")=="Admin" else "Employee","department":profile.get("department") or "Unknown","team":profile.get("team_name") or "Unassigned","account_age_days":age,"timestamp":event["timestamp"],"login_count":len(auth),"failed_login_count":failed,"successful_login_count":max(0,len(auth)-failed),"login_frequency":len(auth),"concurrent_sessions":1,"activities_per_hour":len(hour_events),"activities_per_day":len(day_events),"file_access_count":sum(x["event_type"] in {"FILE_DOWNLOAD","FILE_UPLOAD","SENSITIVE_FILE_ACCESS"} for x in hour_events),"file_upload_count":sum(x["event_type"]=="FILE_UPLOAD" for x in hour_events),"file_download_count":downloads,"ticket_count":sum(x["event_type"]=="TICKET_CREATED" for x in day_events),"task_activity_count":sum(x["event_type"] in {"TASK_CREATED","TASK_COMPLETED"} for x in day_events),"notification_activity_count":sum(x["event_type"]=="NOTIFICATION_VIEW" for x in day_events),"unique_ip_count":len(ips) or 1,"ip_change_frequency":max(0,len(ips)-1),"new_ip_indicator":int(new_ip),"sensitive_file_access":int(event["event_type"]=="SENSITIVE_FILE_ACCESS" or bool(metadata.get("sensitive"))),"privilege_change":int(event["event_type"]=="PRIVILEGE_CHANGE" or bool(metadata.get("privilege_change"))),"unusual_resource_access":int(bool(metadata.get("unusual_resource_access"))),"deviation_from_user_baseline":round(min(6,len(hour_events)/baseline),3),"deviation_from_team_baseline":round(min(6,len(hour_events)/baseline),3),"activity_spike":spike,"login_pattern_deviation":round(min(6,failed/max(1,len(auth))*3 + (2 if new_ip else 0)),3),"source":"security_pipeline","metadata_unavailable":unavailable}

def analyze_event(connection,event):
    features=event_to_features(connection,event);result=predict_activity(features);result["employee_id"]=event.get("employee_id");result["recommended_action"]=_recommend(result);result["analysis_status"]="COMPLETE";result["feature_context"]={"metadata_unavailable":features["metadata_unavailable"]};return result
