"""Grounded query and incident-action layer used by the Security Operations UI."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import sqlite3

INCIDENT_STATUSES = ("NEW", "INVESTIGATING", "MITIGATING", "RESOLVED", "FALSE POSITIVE")
SEVERITIES = {"NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

def ensure_soc_schema(con):
    con.execute("CREATE TABLE IF NOT EXISTS incident_actions (id INTEGER PRIMARY KEY, security_event_id INTEGER NOT NULL, action_type TEXT NOT NULL, note TEXT, analyst_id TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(security_event_id) REFERENCES security_events(id))")
    con.execute("CREATE TABLE IF NOT EXISTS security_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS security_tool_records (id INTEGER PRIMARY KEY, tool_type TEXT NOT NULL, asset TEXT, title TEXT NOT NULL, description TEXT, severity TEXT, risk_score INTEGER, status TEXT NOT NULL, evidence_reference TEXT, recommendation TEXT, source TEXT NOT NULL, metadata_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS forensic_cases (id INTEGER PRIMARY KEY, security_event_id INTEGER NOT NULL UNIQUE, investigator TEXT, conclusion TEXT, evidence_references TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(security_event_id) REFERENCES security_events(id))")
    con.execute("CREATE TABLE IF NOT EXISTS network_observations (id INTEGER PRIMARY KEY, source_ip TEXT, destination_ip TEXT, port INTEGER, protocol TEXT, employee_id TEXT, event_count INTEGER NOT NULL DEFAULT 1, risk_score INTEGER, observed_at TEXT NOT NULL, source TEXT NOT NULL, metadata_json TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS security_import_audit (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, source_format TEXT NOT NULL, imported_count INTEGER NOT NULL, skipped_count INTEGER NOT NULL, created_at TEXT NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS security_api_request_metrics (id INTEGER PRIMARY KEY, endpoint TEXT NOT NULL, method TEXT NOT NULL, status_code INTEGER NOT NULL, duration_ms REAL NOT NULL, created_at TEXT NOT NULL)")
    con.commit()

def _con(path):
    con=sqlite3.connect(path);con.row_factory=sqlite3.Row;ensure_soc_schema(con);return con
def _json(value, default):
    try:return json.loads(value) if value else default
    except (TypeError,ValueError):return default
def _item(row):
    x=dict(row);x['reasons']=_json(x.pop('ai_reasons_json',None),[]);x['metadata']=_json(x.pop('metadata_json',None),{});x['feature_context']=_json(x.pop('ai_feature_context_json',None),{})
    value=(x.get('severity') or '').upper();x['severity_display']=value if value in {'CRITICAL','HIGH','MEDIUM','LOW','NORMAL'} else ('NORMAL' if x.get('ai_prediction')=='Normal' else 'LOW')
    x['attack_type']=x.get('ai_threat_type') or x.get('alert_type') or x.get('event_type') or 'Other';x['risk_display']=int(x['risk_score']) if x.get('risk_score') is not None else None;x['incident_status']=x.get('status') if x.get('status') in INCIDENT_STATUSES else 'NEW';return x

def get_events(path, filters=None, record_type=None, limit=250):
    filters=filters or {};clauses=['1=1'];values=[]
    if record_type:clauses.append('se.record_type=?');values.append(record_type)
    fields={'employee_id':'se.employee_id','event_type':'se.event_type','severity':'se.severity','status':'se.status','source':'se.source','ip_address':'se.ip_address','department':'e.department','team':'t.name'}
    for key,column in fields.items():
        if filters.get(key):clauses.append(column+'=?');values.append(filters[key])
    if filters.get('attack_type'):clauses.append('COALESCE(se.ai_threat_type,se.alert_type,se.event_type)=?');values.append(filters['attack_type'])
    if filters.get('start'):clauses.append('se.timestamp>=?');values.append(filters['start'])
    if filters.get('end'):clauses.append('se.timestamp<=?');values.append(filters['end'])
    values.append(min(max(int(limit),1),500));con=_con(path)
    try:
        query="""SELECT se.*,e.name employee_name,e.department,e.designation,e.status account_status,t.name team_name FROM security_events se LEFT JOIN employees e ON e.employee_id=se.employee_id LEFT JOIN teams t ON t.id=e.team_id WHERE """+' AND '.join(clauses)+' ORDER BY se.timestamp DESC,se.id DESC LIMIT ?'
        return [_item(row) for row in con.execute(query,values).fetchall()]
    finally:con.close()

def event_detail(path, record_id):
    con=_con(path)
    try:
        row=con.execute("SELECT se.*,e.name employee_name,e.department,e.designation,e.status account_status,t.name team_name FROM security_events se LEFT JOIN employees e ON e.employee_id=se.employee_id LEFT JOIN teams t ON t.id=e.team_id WHERE se.id=?",(record_id,)).fetchone()
        if not row:return None
        event=_item(row);event['actions']=[dict(x) for x in con.execute('SELECT * FROM incident_actions WHERE security_event_id=? ORDER BY created_at DESC',(record_id,)).fetchall()]
        event['timeline']=[_item(x) for x in con.execute('SELECT * FROM security_events WHERE employee_id=? AND timestamp<=? ORDER BY timestamp DESC LIMIT 30',(event.get('employee_id'),event['timestamp'])).fetchall()][::-1];return event
    finally:con.close()

def metrics(path, filters=None):
    events=get_events(path,filters,'EVENT',500);alerts=get_events(path,filters,'ALERT',500);all_items=events+alerts;threats=[x for x in events if x.get('ai_prediction')=='Threat']
    return {'total_events':len(events),'alerts':len(alerts),'active_threats':sum(x['incident_status'] not in {'RESOLVED','FALSE POSITIVE'} for x in threats),'critical':sum(x['severity_display']=='CRITICAL' for x in all_items),'high':sum(x['severity_display']=='HIGH' for x in all_items),'medium':sum(x['severity_display']=='MEDIUM' for x in all_items),'suspicious':sum(x.get('ai_prediction')=='Suspicious' for x in events),'resolved':sum(x['incident_status']=='RESOLVED' for x in all_items),'false_positive':sum(x['incident_status']=='FALSE POSITIVE' for x in all_items),'ai_processed':sum(x.get('ai_status')=='COMPLETE' for x in events),'confirmed_threats':len(threats)}

def analytics(path, filters=None):
    events=get_events(path,filters,'EVENT',500);alerts=get_events(path,filters,'ALERT',500);all_items=events+alerts;trend=defaultdict(lambda:[0,0,0,0])
    for x in events:
        d=(x.get('timestamp') or '')[:10] or 'Unknown';trend[d][0]+=1;trend[d][1]+=x.get('ai_prediction')=='Threat';trend[d][2]+=x.get('ai_prediction')=='Suspicious';trend[d][3]+=x['severity_display']=='CRITICAL'
    users=defaultdict(lambda:{'employee_id':'','name':'Unknown','risk':0,'risk_count':0,'events':0,'threats':0,'suspicious':0})
    for x in events:
        u=users[x.get('employee_id') or 'Unknown'];u.update(employee_id=x.get('employee_id') or 'Unknown',name=x.get('employee_name') or x.get('employee_id') or 'Unknown');u['risk']+=x['risk_display'] or 0;u['risk_count']+=x['risk_display'] is not None;u['events']+=1;u['threats']+=x.get('ai_prediction')=='Threat';u['suspicious']+=x.get('ai_prediction')=='Suspicious'
    ranks=sorted(users.values(),key=lambda u:(u['risk'],u['threats']),reverse=True)[:10]
    for u in ranks:u['average_risk']=round(u['risk']/u['risk_count'],1) if u['risk_count'] else None
    m=metrics(path,filters);risk=[x['risk_display'] for x in events if x.get('risk_score') is not None];m.update(average_risk=round(sum(risk)/len(risk),1) if risk else None,threat_rate=round(100*m['confirmed_threats']/len(events),1) if events else None,suspicious_rate=round(100*m['suspicious']/len(events),1) if events else None,false_positive_rate=round(100*m['false_positive']/len(all_items),1) if all_items else None,detection_rate=round(100*m['alerts']/len(events),1) if events else None,average_resolution_time='Insufficient Data')
    labels=sorted(trend);return {'metrics':m,'trend':{'labels':labels,'events':[trend[d][0] for d in labels],'threats':[trend[d][1] for d in labels],'suspicious':[trend[d][2] for d in labels],'critical':[trend[d][3] for d in labels]},'attacks':dict(Counter(x['attack_type'] for x in all_items)),'severity':dict(Counter(x['severity_display'] for x in all_items)),'departments':dict(Counter(x.get('department') or 'Unassigned' for x in all_items)),'rankings':ranks,'funnel':[len(events),len(alerts),m['ai_processed'],m['confirmed_threats'],m['resolved']]}

def summary(path, filters=None):
    data=analytics(path,filters);m=data['metrics']
    if not m['total_events']:return 'No security events are available for the selected period.'
    top=lambda values:max(values,key=values.get) if values else 'No classified data';return f"{m['total_events']} security events were processed. {m['suspicious']} were suspicious and {m['confirmed_threats']} were threats. {m['critical']} critical records require attention. {top(data['attacks'])} is the most common classification, while {top(data['departments'])} has the most recorded security activity."

def recommendations(path, filters=None):
    return [{'event':x,'priority':x['severity_display'],'evidence':x['reasons'] or [x.get('description') or 'Model classification'],'action':x.get('ai_recommended_action') or 'Review the event and related employee activity.'} for x in get_events(path,filters,'EVENT',500) if x.get('ai_prediction') in {'Threat','Suspicious'}]

def record_action(path, record_id, action, note, analyst_id):
    if action not in {'START_INVESTIGATION','START_MITIGATION','RESOLVE','FALSE_POSITIVE','NOTE'}:raise ValueError('Unsupported action')
    status={'START_INVESTIGATION':'INVESTIGATING','START_MITIGATION':'MITIGATING','RESOLVE':'RESOLVED','FALSE_POSITIVE':'FALSE POSITIVE'}.get(action);con=_con(path)
    try:
        if not con.execute('SELECT 1 FROM security_events WHERE id=?',(record_id,)).fetchone():raise ValueError('Security event not found')
        if status:con.execute('UPDATE security_events SET status=? WHERE id=?',(status,record_id))
        con.execute('INSERT INTO incident_actions(security_event_id,action_type,note,analyst_id,created_at) VALUES(?,?,?,?,?)',(record_id,action,(note or '')[:2000],analyst_id,datetime.now(timezone.utc).isoformat()));con.commit()
    finally:con.close()

def tool_records(path, tool_type, filters=None):
    filters=filters or {};clauses=['tool_type=?'];values=[tool_type]
    for key in ('severity','asset','status'):
        if filters.get(key):clauses.append(key+'=?');values.append(filters[key])
    con=_con(path)
    try:return [dict(x) for x in con.execute('SELECT * FROM security_tool_records WHERE '+' AND '.join(clauses)+' ORDER BY updated_at DESC,id DESC',values).fetchall()]
    finally:con.close()
def add_tool_record(path, tool_type, payload, source='ANALYST'): 
    now=datetime.now(timezone.utc).isoformat();title=(payload.get('title') or '').strip();status=(payload.get('status') or 'OPEN').upper();severity=(payload.get('severity') or 'LOW').upper();risk=payload.get('risk_score')
    if not title:raise ValueError('title is required')
    if severity not in SEVERITIES:raise ValueError('invalid severity')
    if risk not in (None,'') and (not str(risk).isdigit() or not 0<=int(risk)<=100):raise ValueError('risk score must be 0-100')
    con=_con(path)
    try:
        con.execute('INSERT INTO security_tool_records(tool_type,asset,title,description,severity,risk_score,status,evidence_reference,recommendation,source,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(tool_type,(payload.get('asset') or '')[:200],title[:300],(payload.get('description') or '')[:4000],severity,int(risk) if risk not in (None,'') else None,status[:40],(payload.get('evidence_reference') or '')[:500],(payload.get('recommendation') or '')[:2000],source,'{}',now,now));con.commit()
    finally:con.close()
def forensic_case(path, record_id, investigator, conclusion='', evidence_references=''):
    now=datetime.now(timezone.utc).isoformat();con=_con(path)
    try:
        con.execute('INSERT INTO forensic_cases(security_event_id,investigator,conclusion,evidence_references,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(security_event_id) DO UPDATE SET investigator=excluded.investigator,conclusion=excluded.conclusion,evidence_references=excluded.evidence_references,updated_at=excluded.updated_at',(record_id,investigator,(conclusion or '')[:4000],(evidence_references or '')[:2000],now,now));con.commit()
    finally:con.close()
def api_metrics(path):
    con=_con(path)
    try:
        rows=con.execute('SELECT * FROM security_api_request_metrics ORDER BY created_at DESC LIMIT 250').fetchall();items=[dict(x) for x in rows];return {'requests':len(items),'failed':sum(x['status_code']>=400 for x in items),'last_request':items[0] if items else None,'average_ms':round(sum(x['duration_ms'] for x in items)/len(items),1) if items else None}
    finally:con.close()

def ip_statistics(path):
    result=defaultdict(lambda:{'ip':'','events':0,'failed':0,'users':set(),'threats':0,'suspicious':0,'risk_values':[],'attack_types':set(),'first':None,'last':None})
    for x in get_events(path,None,'EVENT',500):
        if not x.get('ip_address'):continue
        v=result[x['ip_address']];v['ip']=x['ip_address'];v['events']+=1;v['failed']+=x.get('event_type')=='LOGIN_FAILED';v['threats']+=x.get('ai_prediction')=='Threat';v['suspicious']+=x.get('ai_prediction')=='Suspicious';v['risk_values'].append(x['risk_display']) if x['risk_display'] is not None else None;v['attack_types'].add(x['attack_type']);v['users'].add(x.get('employee_id'));v['first']=min(v['first'],x['timestamp']) if v['first'] else x['timestamp'];v['last']=max(v['last'],x['timestamp']) if v['last'] else x['timestamp']
    values=[]
    for v in result.values():v['users']=len(v['users']-{None});v['risk_score']=round(sum(v['risk_values'])/len(v['risk_values'])) if v['risk_values'] else None;v['risk']='CRITICAL' if (v['risk_score'] or 0)>=85 else 'HIGH' if (v['risk_score'] or 0)>=70 or v['threats'] else 'MEDIUM' if (v['risk_score'] or 0)>=50 or v['suspicious'] or v['failed']>=5 else 'LOW';v['attack_types']=sorted(v['attack_types']);values.append(v)
    return sorted(values,key=lambda v:(v['threats'],v['failed'],v['events']),reverse=True)

def agent_answer(path, question):
    q=(question or '').strip().lower();data=analytics(path);m=data['metrics']
    if not q:return 'Ask about critical threats, an employee ID, suspicious IPs, common attacks, or the security summary.'
    employee=next((part.upper().strip('.,?') for part in q.split() if part.upper().startswith('EMP')),None)
    if employee:
        events=get_events(path,{'employee_id':employee},'EVENT',100)
        if not events:return f'No security events were found for {employee}.'
        threats=sum(x.get('ai_prediction')=='Threat' for x in events);suspicious=sum(x.get('ai_prediction')=='Suspicious' for x in events);latest=events[0]
        if 'why' in q or 'high risk' in q:return f"{employee} is associated with {threats} threats and {suspicious} suspicious events. Latest evidence: "+('; '.join(latest['reasons']) or 'no recorded model reasons')+'.'
        return f"{employee} has {len(events)} recorded security events: {threats} threats and {suspicious} suspicious classifications. Latest classification: {latest.get('ai_prediction') or 'unavailable'} / {latest['attack_type']}."
    if 'highest risk' in q or 'top user' in q:
        top=data['rankings'][0] if data['rankings'] else None;return f"Highest-risk user: {top['employee_id']} ({top['name']}), cumulative risk {top['risk']} across {top['events']} events." if top else 'Insufficient data to rank users.'
    if 'unresolved' in q:return f"There are {m['active_threats']} unresolved model-confirmed threats."
    if 'mitigation' in q:
        recs=recommendations(path);return recs[0]['action'] if recs else 'No current threat has a recorded mitigation recommendation.'
    if 'compare' in q:return 'Comparison requires explicit date filters; use Analytics date ranges to compare recorded periods without inventing a trend.'
    if 'critical' in q:return f"There are {m['critical']} critical security records in the current dataset."
    if 'ip' in q:return 'Suspicious IPs: '+(', '.join(x['ip'] for x in ip_statistics(path)[:5]) or 'no IP-addressed events are available')+'.'
    if any(w in q for w in ('summary','situation','today','risk increase')):return summary(path)
    if any(w in q for w in ('common','attack','brute')):return 'Most common classifications: '+(', '.join(f'{name} ({count})' for name,count in sorted(data['attacks'].items(),key=lambda x:x[1],reverse=True)[:3]) or 'insufficient data')+'.'
    return 'I can answer grounded questions about critical threats, employee history, IP activity, common attacks, and the current security summary.'
