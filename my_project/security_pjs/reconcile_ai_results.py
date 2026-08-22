"""Safely re-run existing inference for incomplete historical security events."""
import argparse
import json
import sqlite3
from pathlib import Path
from .ai_adapter import analyze_event
from .alert_manager import ensure_security_schema, store_ai_result

REQUIRED=("ai_prediction","ai_threat_type","risk_score","severity","ai_confidence","ai_anomaly_detected","ai_reasons_json","ai_recommended_action")

def _needs_reconciliation(row):
    if row["ai_status"] != "COMPLETE": return True
    if any(row[field] is None or row[field]=="" for field in REQUIRED): return True
    return str(row["severity"]).upper() not in {"LOW","MEDIUM","HIGH","CRITICAL","NORMAL"}

def reconcile(database_path, dry_run=False):
    """Return a deterministic audit report; source events and IDs are never replaced."""
    con=sqlite3.connect(Path(database_path));con.row_factory=sqlite3.Row;ensure_security_schema(con)
    con.execute("CREATE TABLE IF NOT EXISTS ai_reconciliation_audit (id INTEGER PRIMARY KEY,event_id TEXT NOT NULL,action TEXT NOT NULL,detail TEXT,processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    rows=con.execute("SELECT * FROM security_events WHERE record_type='EVENT' ORDER BY id").fetchall();report={"total_ai_events":len(rows),"reconciled":0,"unchanged":0,"failed":0,"failures":[]}
    try:
        for row in rows:
            if not _needs_reconciliation(row):report["unchanged"]+=1;continue
            event={"event_id":row["event_id"],"employee_id":row["employee_id"],"event_type":row["event_type"],"timestamp":row["timestamp"],"ip_address":row["ip_address"],"resource":row["resource"],"source":row["source"],"metadata":json.loads(row["metadata_json"] or "{}")}
            try:
                result=analyze_event(con,event)
                if not dry_run:store_ai_result(con,event["event_id"],result);con.execute("INSERT INTO ai_reconciliation_audit(event_id,action,detail) VALUES(?,?,?)",(event["event_id"],"RECONCILED",json.dumps({"prediction":result.get("prediction"),"risk_score":result.get("risk_score")})))
                report["reconciled"]+=1
            except Exception as exc:
                report["failed"]+=1;report["failures"].append({"event_id":row["event_id"],"error":str(exc)})
                if not dry_run:con.execute("INSERT INTO ai_reconciliation_audit(event_id,action,detail) VALUES(?,?,?)",(row["event_id"],"FAILED",str(exc)[:1000]))
        if not dry_run:con.commit()
        return report
    finally:con.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument("database",nargs="?",default=str(Path(__file__).resolve().parents[1]/"company.db"));parser.add_argument("--dry-run",action="store_true");args=parser.parse_args();report=reconcile(args.database,args.dry_run);print(json.dumps(report,indent=2));return 1 if report["failed"] else 0
if __name__=="__main__":raise SystemExit(main())
