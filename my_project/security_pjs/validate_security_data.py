"""Validation report for AI/security-event data. Exits non-zero if invalid records remain."""
import argparse
import json
import sqlite3
from pathlib import Path

SEVERITIES={"NORMAL","LOW","MEDIUM","HIGH","CRITICAL"};PREDICTIONS={"NORMAL","SUSPICIOUS","THREAT"};STATUSES={"NEW","INVESTIGATING","MITIGATING","RESOLVED","FALSE POSITIVE"}
def validate(database_path):
    con=sqlite3.connect(Path(database_path));con.row_factory=sqlite3.Row
    try:
        rows=con.execute("SELECT * FROM security_events WHERE record_type='EVENT'").fetchall();issues=[];seen=set()
        for row in rows:
            item=[];prediction=(row["ai_prediction"] or "").upper();severity=(row["severity"] or "").upper();status=(row["status"] or "").upper();risk=row["risk_score"]
            if not row["event_id"]:item.append("missing event_id")
            elif row["event_id"] in seen:item.append("duplicate event_id")
            else:seen.add(row["event_id"])
            if not row["timestamp"]:item.append("missing timestamp")
            if status not in STATUSES:item.append("invalid status")
            if row["ai_status"]=="COMPLETE":
                if prediction not in PREDICTIONS:item.append("invalid prediction")
                if severity not in SEVERITIES:item.append("invalid severity")
                if risk is None or not 0<=int(risk)<=100:item.append("missing or invalid risk score")
                if not row["ai_threat_type"]:item.append("missing threat type")
                if row["ai_confidence"] is None:item.append("missing confidence")
                if not row["ai_reasons_json"]:item.append("missing reasons")
                if not row["ai_recommended_action"]:item.append("missing recommendation")
                if prediction=="THREAT" and (risk is None or severity in {"INFO","NORMAL","LOW"}):item.append("inconsistent threat severity/risk")
            if item:issues.append({"event_id":row["event_id"],"issues":item})
        return {"total_ai_events":len(rows),"valid":len(rows)-len(issues),"invalid":len(issues),"invalid_records":issues}
    finally:con.close()
def main():
    parser=argparse.ArgumentParser();parser.add_argument("database",nargs="?",default=str(Path(__file__).resolve().parents[1]/"company.db"));args=parser.parse_args();report=validate(args.database);print(json.dumps(report,indent=2));return 1 if report["invalid"] else 0
if __name__=="__main__":raise SystemExit(main())
