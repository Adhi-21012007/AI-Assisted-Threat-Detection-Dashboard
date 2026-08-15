import logging, sqlite3, uuid, json
from pathlib import Path
from .event_normalizer import normalize_activity_log, normalize_event
from .alert_manager import ensure_security_schema, store_event, store_alert, store_ai_result, mark_ai_failed
from .ai_adapter import analyze_event
from .firewall_engine import FirewallEngine

logger=logging.getLogger("security_pjs")

def _connection(database_path):
    con=sqlite3.connect(Path(database_path));con.row_factory=sqlite3.Row;ensure_security_schema(con);return con

def process_event(database_path, event_payload, already_normalized=False):
    event=dict(event_payload) if already_normalized else normalize_event(event_payload)
    event.setdefault("event_id", str(uuid.uuid4()))
    event.setdefault("metadata", {})
    con=_connection(database_path)
    try:
        created=store_event(con,event)
        if not created:
            existing=con.execute("SELECT * FROM security_events WHERE event_id=? AND record_type='EVENT'",(event["event_id"],)).fetchone()
            ai_result={"analysis_status":existing["ai_status"] if existing else "UNKNOWN"}
            if existing and existing["ai_status"]=='FAILED':
                retry_event={"event_id":existing["event_id"],"employee_id":existing["employee_id"],"event_type":existing["event_type"],"timestamp":existing["timestamp"],"ip_address":existing["ip_address"],"resource":existing["resource"],"source":existing["source"],"metadata":json.loads(existing["metadata_json"] or "{}")}
                try:ai_result=analyze_event(con,retry_event);store_ai_result(con,event["event_id"],ai_result)
                except Exception:logger.exception("AI retry failed for event %s",event["event_id"])
            return {"event":event,"created":False,"decision":"NORMAL","alerts":[],"ai_result":ai_result}
        alerts=[]
        for candidate in FirewallEngine().inspect(con,event):
            stored=store_alert(con,event,candidate)
            if stored: logger.warning("Firewall rule %s triggered for %s",stored["triggered_rule"],stored.get("employee_id"));alerts.append(stored)
        decision="SECURITY_ALERT" if any(a["severity"] in {"HIGH","CRITICAL"} for a in alerts) else "SUSPICIOUS" if alerts else "NORMAL"
        try:
            ai_result=analyze_event(con,event);store_ai_result(con,event["event_id"],ai_result)
        except Exception:
            logger.exception("AI inference failed for event %s",event["event_id"]);mark_ai_failed(con,event["event_id"]);ai_result={"analysis_status":"FAILED"}
        return {"event":event,"created":True,"decision":decision,"alerts":alerts,"ai_result":ai_result}
    finally: con.close()

def process_activity_log(database_path, activity_log_id):
    con=_connection(database_path)
    try:
        row=con.execute("SELECT * FROM activity_logs WHERE id=?",(activity_log_id,)).fetchone()
        if not row: raise ValueError("activity log not found")
        return process_event(database_path,normalize_activity_log(dict(row)),already_normalized=True)
    finally:con.close()
