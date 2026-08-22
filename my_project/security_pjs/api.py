import ipaddress, logging, os, sqlite3, time
from datetime import datetime
from flask import Blueprint, current_app, g, jsonify, request
from . import config
from .event_normalizer import normalize_event, VALID_EVENT_TYPES
from .event_processor import process_event
from .alert_manager import ensure_security_schema

logger=logging.getLogger("security_api")
security_api=Blueprint("security_api",__name__,url_prefix="/api/security")

def _error(message,status=400):return jsonify({"error":{"message":message,"status":status}}),status
def _api_key_required():
    expected=os.environ.get("SECURITY_API_KEY")
    return bool(expected) and request.headers.get("X-API-Key")!=expected
def _validate_event(payload):
    if not isinstance(payload,dict):raise ValueError("JSON object required")
    if not payload.get("employee_id") or not str(payload["employee_id"]).isalnum():raise ValueError("valid employee_id is required")
    if str(payload.get("event_type","")).upper() not in VALID_EVENT_TYPES:raise ValueError("valid event_type is required")
    if payload.get("ip_address"):
        try:ipaddress.ip_address(payload["ip_address"])
        except ValueError:raise ValueError("ip_address must be valid")
    return normalize_event(payload)
def _connection():
    con=sqlite3.connect(current_app.config["DATABASE"]);con.row_factory=sqlite3.Row;ensure_security_schema(con);return con
def _employee_exists(employee_id):
    con=_connection()
    try:return con.execute("SELECT 1 FROM employees WHERE employee_id=?",(employee_id,)).fetchone() is not None
    finally:con.close()

@security_api.before_app_request
def request_limit():
    if request.path.startswith('/api/security'):g.security_api_started=time.perf_counter()
    if request.path.startswith("/api/security") and request.content_length and request.content_length>config.MAX_API_BYTES:return _error("request body too large",413)

@security_api.after_app_request
def audit_api_request(response):
    if not request.path.startswith('/api/security'):return response
    try:
        from .dashboard_data import ensure_soc_schema
        con=sqlite3.connect(current_app.config['DATABASE']);ensure_security_schema(con);ensure_soc_schema(con)
        con.execute('INSERT INTO security_api_request_metrics(endpoint,method,status_code,duration_ms,created_at) VALUES(?,?,?,?,?)',(request.path,request.method,response.status_code,round((time.perf_counter()-getattr(g,'security_api_started',time.perf_counter()))*1000,2),datetime.now().astimezone().isoformat()));con.commit();con.close()
    except sqlite3.Error:logger.exception('Security API audit write failed')
    return response

@security_api.route("/health")
def health():
    try:
        con=_connection();con.execute("SELECT 1");con.close();return jsonify({"status":"healthy","service":"security-api","firewall":"active","database":"connected"})
    except sqlite3.Error:
        logger.exception("Security API database health check failed");return _error("service unavailable",503)

@security_api.route("/events",methods=["POST"])
def post_event():
    if _api_key_required():return _error("unauthorized",401)
    try:
        event=_validate_event(request.get_json(silent=True))
        if not _employee_exists(event["employee_id"]):return _error("employee not found",404)
        result=process_event(current_app.config["DATABASE"],event,already_normalized=True);logger.info("Security event accepted: %s",event["event_type"])
        return jsonify({"event":result["event"],"decision":result["decision"],"alerts":result["alerts"],"ai_result":result.get("ai_result")}),201
    except ValueError as exc:logger.warning("Invalid security event: %s",exc);return _error(str(exc),400)
    except sqlite3.Error:logger.exception("Security event database error");return _error("service unavailable",503)
    except Exception:logger.exception("Security event processing failed");return _error("internal server error",500)

@security_api.route("/alerts",methods=["POST"])
def post_alert():
    if _api_key_required():return _error("unauthorized",401)
    payload=request.get_json(silent=True)
    if not isinstance(payload,dict) or not payload.get("employee_id") or not payload.get("alert_type") or not payload.get("severity"):return _error("employee_id, alert_type, and severity are required")
    try:
        con=_connection();ensure_security_schema(con);from .alert_manager import store_alert
        event={"event_id":payload.get("event_id") or "external-alert","employee_id":payload["employee_id"],"event_type":payload.get("event_type","OTHER"),"timestamp":payload.get("timestamp") or datetime.now().astimezone().isoformat(),"ip_address":payload.get("ip_address"),"resource":payload.get("resource")}
        alert={key:payload.get(key) for key in ["alert_type","severity","risk_score","description","triggered_rule","recommended_action"]};alert.update({"risk_score":int(alert["risk_score"] or 0),"description":alert["description"] or "External security alert","triggered_rule":alert["triggered_rule"] or "EXTERNAL_ALERT","recommended_action":alert["recommended_action"] or "Review alert details."})
        saved=store_alert(con,event,alert);con.close();return jsonify({"alert":saved,"deduplicated":saved is None}),201
    except (ValueError,sqlite3.Error):logger.exception("Alert submission failed");return _error("invalid alert",400)

def _list(record_type):
    try:
        allowed={"employee_id","event_type","severity","alert_type","status"};clauses=["record_type=?"];args=[record_type]
        for key,value in request.args.items():
            if key in allowed and value:clauses.append(f"{key}=?");args.append(value)
        for key,op in [("start_time",">="),("end_time","<=")]:
            if request.args.get(key):clauses.append(f"timestamp {op} ?");args.append(request.args[key])
        con=_connection();rows=con.execute("SELECT * FROM security_events WHERE "+" AND ".join(clauses)+" ORDER BY timestamp DESC LIMIT 250",args).fetchall();con.close()
        items=[]
        for row in rows:
            item=dict(row)
            for field in ("metadata_json","ai_reasons_json","ai_feature_context_json"):
                if item.get(field):
                    try:item[field.removesuffix("_json")]=__import__('json').loads(item[field])
                    except ValueError:pass
                item.pop(field,None)
            items.append(item)
        return jsonify({"items":items,"count":len(items)})
    except sqlite3.Error:logger.exception("Security event query failed");return _error("service unavailable",503)
@security_api.route("/events")
def get_events():return _list("EVENT")
@security_api.route("/alerts")
def get_alerts():return _list("ALERT")
