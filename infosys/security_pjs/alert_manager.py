from datetime import datetime, timedelta
import json, sqlite3, uuid
from . import config

def ensure_security_schema(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY, event_type TEXT, severity TEXT, description TEXT, timestamp TEXT, status TEXT DEFAULT 'Open')""")
    existing={row[1] for row in connection.execute("PRAGMA table_info(security_events)")}
    additions=[("event_id","TEXT"),("employee_id","TEXT"),("source","TEXT"),("alert_type","TEXT"),("risk_score","INTEGER"),("triggered_rule","TEXT"),("recommended_action","TEXT"),("metadata_json","TEXT"),("record_type","TEXT DEFAULT 'ALERT'"),("ip_address","TEXT"),("resource","TEXT"),("ai_prediction","TEXT"),("ai_threat_type","TEXT"),("ai_confidence","REAL"),("ai_anomaly_detected","INTEGER"),("ai_reasons_json","TEXT"),("ai_recommended_action","TEXT"),("ai_processed_at","TEXT"),("ai_status","TEXT"),("ai_feature_context_json","TEXT")]
    for name, kind in additions:
        if name not in existing: connection.execute(f"ALTER TABLE security_events ADD COLUMN {name} {kind}")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_security_events_event_id ON security_events(event_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_security_events_lookup ON security_events(record_type,employee_id,timestamp)")
    connection.execute("UPDATE security_events SET record_type=COALESCE(record_type,'ALERT')")
    connection.execute("UPDATE security_events SET status='NEW' WHERE record_type IN ('EVENT','ALERT') AND UPPER(COALESCE(status,'')) NOT IN ('NEW','INVESTIGATING','MITIGATING','RESOLVED','FALSE POSITIVE')")
    connection.commit()

def _row_to_event(row):
    event=dict(row); event["metadata"]=json.loads(event.pop("metadata_json") or "{}")
    return event

def recent_events(connection, employee_id, since, record_type="EVENT"):
    connection.row_factory=sqlite3.Row
    data=connection.execute("SELECT * FROM security_events WHERE record_type=? AND employee_id=? AND timestamp>=? ORDER BY timestamp",(record_type,employee_id,since.isoformat())).fetchall()
    return [_row_to_event(row) for row in data]

def store_event(connection,event):
    existing=connection.execute("SELECT id FROM security_events WHERE event_id=?",(event["event_id"],)).fetchone()
    if existing:return False
    metadata={**(event.get("metadata") or {}),"activity_status":event.get("status")}
    connection.execute("""INSERT INTO security_events(event_id,employee_id,event_type,source,severity,description,timestamp,status,metadata_json,record_type,ip_address,resource)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",(event["event_id"],event.get("employee_id"),event["event_type"],event.get("source"),"INFO",metadata.get("description"),event["timestamp"],"NEW",json.dumps(metadata),"EVENT",event.get("ip_address"),event.get("resource")))
    connection.commit();return True

def is_duplicate(connection, employee_id, alert_type, now):
    cutoff=(now-timedelta(minutes=config.ALERT_DEDUP_MINUTES)).isoformat()
    return connection.execute("SELECT 1 FROM security_events WHERE record_type='ALERT' AND employee_id=? AND alert_type=? AND timestamp>=? LIMIT 1",(employee_id,alert_type,cutoff)).fetchone() is not None

def store_alert(connection,event,alert):
    now=datetime.fromisoformat(event["timestamp"])
    if is_duplicate(connection,event.get("employee_id"),alert["alert_type"],now):return None
    alert_id=str(uuid.uuid4())
    connection.execute("""INSERT INTO security_events(event_id,employee_id,event_type,source,alert_type,severity,risk_score,description,triggered_rule,timestamp,status,recommended_action,metadata_json,record_type,ip_address,resource)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(alert_id,event.get("employee_id"),event["event_type"],"firewall_engine",alert["alert_type"],alert["severity"],alert["risk_score"],alert["description"],alert["triggered_rule"],event["timestamp"],"NEW",alert["recommended_action"],json.dumps({"source_event_id":event["event_id"]}),"ALERT",event.get("ip_address"),event.get("resource")))
    connection.commit();return {"alert_id":alert_id,"event_id":event["event_id"],"employee_id":event.get("employee_id"),**alert,"source":"firewall_engine","timestamp":event["timestamp"],"status":"NEW"}

def store_ai_result(connection, event_id, result):
    connection.execute("""UPDATE security_events SET severity=?,risk_score=?,ai_prediction=?,ai_threat_type=?,ai_confidence=?,ai_anomaly_detected=?,ai_reasons_json=?,ai_recommended_action=?,ai_processed_at=?,ai_status=?
        WHERE event_id=? AND record_type='EVENT'""",(str(result.get("severity") or "LOW").upper(),result.get("risk_score"),result.get("prediction"),result.get("threat_type"),result.get("confidence"),int(bool(result.get("anomaly_detected"))),json.dumps(result.get("reasons") or []),result.get("recommended_action"),result.get("processed_at"),result.get("analysis_status","COMPLETE"),event_id))
    connection.execute("UPDATE security_events SET ai_feature_context_json=? WHERE event_id=? AND record_type='EVENT'",(json.dumps(result.get("feature_context") or {}),event_id))
    connection.commit()

def mark_ai_failed(connection,event_id):
    connection.execute("UPDATE security_events SET ai_status='FAILED' WHERE event_id=? AND record_type='EVENT'",(event_id,));connection.commit()
