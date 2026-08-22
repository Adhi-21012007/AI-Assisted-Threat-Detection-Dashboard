"""Normalise portal activity logs and external payloads without fabricating data."""
from datetime import datetime, timezone
import uuid

ACTIVITY_MAP = {
    "login": ("LOGIN_SUCCESS", "SUCCESS"), "failed login": ("LOGIN_FAILED", "FAILED"), "logout": ("LOGOUT", "SUCCESS"),
    "check-in": ("ATTENDANCE_CHECK_IN", "SUCCESS"), "check-out": ("ATTENDANCE_CHECK_OUT", "SUCCESS"),
    "break start": ("BREAK_START", "SUCCESS"), "break end": ("BREAK_END", "SUCCESS"),
    "task creation": ("TASK_CREATED", "SUCCESS"), "task completion": ("TASK_COMPLETED", "SUCCESS"),
    "ticket creation": ("TICKET_CREATED", "SUCCESS"), "calendar interaction": ("CALENDAR_VIEW", "SUCCESS"),
    "notification viewed": ("NOTIFICATION_VIEW", "SUCCESS"), "employee edited": ("PROFILE_UPDATED", "SUCCESS"),
    "employee deactivated": ("ACCOUNT_DEACTIVATED", "SUCCESS"), "attendance corrected": ("ATTENDANCE_CORRECTED", "SUCCESS"),
    "privilege change": ("PRIVILEGE_CHANGE", "SUCCESS"), "file upload": ("FILE_UPLOAD", "SUCCESS"), "file download": ("FILE_DOWNLOAD", "SUCCESS"),
}

VALID_EVENT_TYPES = set(event for event, _ in ACTIVITY_MAP.values()) | {"SENSITIVE_FILE_ACCESS", "PRIVILEGE_CHANGE", "FILE_DOWNLOAD", "FILE_UPLOAD", "LOGIN_SUCCESS", "LOGIN_FAILED", "OTHER"}

def normalise_timestamp(value):
    if not value: return datetime.now(timezone.utc).isoformat()
    try:
        parsed=datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).isoformat()
    except ValueError: raise ValueError("timestamp must be ISO-8601")

def normalize_activity_log(row):
    activity=(row.get("activity_type") or "").strip().lower(); event_type,status=ACTIVITY_MAP.get(activity,("OTHER","UNKNOWN"))
    return {"event_id":f"activity-{row['id']}" if row.get("id") is not None else str(uuid.uuid4()), "employee_id":row.get("employee_id") or row.get("user_id"),
            "event_type":event_type,"timestamp":normalise_timestamp(row.get("timestamp")),"ip_address":row.get("ip_address"),"user_agent":None,
            "source":"admin_portal" if row.get("user_type")=="Admin" else "employee_portal","status":status,"resource":None,
            "metadata":{"activity_log_id":row.get("id"),"original_activity_type":row.get("activity_type"),"description":row.get("description"),"user_type":row.get("user_type")}}

def normalize_event(payload):
    metadata=payload.get("metadata") or {}
    event_type=str(payload.get("event_type","")).upper().strip()
    if event_type not in VALID_EVENT_TYPES: raise ValueError("unsupported event_type")
    return {"event_id":payload.get("event_id") or str(uuid.uuid4()),"employee_id":payload.get("employee_id"),"event_type":event_type,
            "timestamp":normalise_timestamp(payload.get("timestamp")),"ip_address":payload.get("ip_address"),"user_agent":payload.get("user_agent"),
            "source":payload.get("source") or "security_api","status":payload.get("status") or "UNKNOWN","resource":payload.get("resource"),"metadata":metadata}
