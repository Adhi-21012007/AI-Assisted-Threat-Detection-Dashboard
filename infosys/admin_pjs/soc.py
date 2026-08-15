"""Security Operations Center routes; all analytics are derived from company.db."""
import csv
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from security_pjs.dashboard_data import add_tool_record, analytics, agent_answer, api_metrics, event_detail, forensic_case, get_events, incidents, intelligence_records, ip_statistics, recommendations, record_action, summary, tool_records
from security_pjs.intelligence import analyse_email, analyse_image, analyse_ip, analyse_pcap, analyse_qr, analyse_url, copilot_answer, generate_report, parse_nmap_xml, persist_finding
from security_pjs.event_normalizer import normalize_event
from security_pjs.event_processor import process_event

soc=Blueprint('soc',__name__,url_prefix='/security-operations')
PAGES={
 'dashboard':'Dashboard','analytics':'Analytics','ai_summary':'AI Summary','recommendations':'AI Recommendations','agent':'AI Security Agent','copilot':'AI Security Copilot','url_analysis':'URL Analysis','email_security':'Email Security','image_phishing':'Image Phishing','qr_security':'QR Security','virustotal':'VirusTotal Intelligence','nmap':'Nmap Analysis','wireshark':'Wireshark Analysis','reports':'Security Reports','static_data':'Static Data','live_api':'Live API','rest_api':'REST API','ip_intelligence':'IP Intelligence','network_intelligence':'Network Intelligence','statistics':'Statistics','active_threats':'Active Threats','investigations':'Threat Investigation','mitigation':'Risk Mitigation','siem':'SIEM & Monitoring','events':'Security Events','vulnerabilities':'Vulnerability Assessment','pentesting':'Penetration Testing','web_security':'Web Application Security','forensics':'Digital Forensics','api_keys':'API Keys','settings':'Settings'}

def admin_required(view):
    @wraps(view)
    def wrapped(*args,**kwargs):
        if not session.get('admin_id'):return redirect(url_for('login'))
        return view(*args,**kwargs)
    return wrapped
def _filters():
    values={key:request.args.get(key,'').strip() for key in ('employee_id','event_type','severity','status','source','ip_address','department','team','attack_type','start','end')}
    hours={'24h':24,'7d':168,'30d':720}.get(request.args.get('range'))
    if hours and not values['start']:values['start']=(datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat()
    return values
@soc.before_request
def csrf_protect():
    if request.method=='POST' and request.form.get('_csrf')!=session.get('soc_csrf'):
        abort(400)
def _render(page, **extra):
    path=current_app.config['DATABASE'];filters=_filters();data=analytics(path,filters);events=get_events(path,filters,'EVENT',250);alerts=get_events(path,filters,'ALERT',250)
    choices={'employees':sorted({x.get('employee_id') for x in events if x.get('employee_id')}),'departments':sorted({x.get('department') for x in events if x.get('department')}),'teams':sorted({x.get('team_name') for x in events if x.get('team_name')}),'attacks':sorted(set(data['attacks']))}
    tool_type={'vulnerabilities':'VULNERABILITY','pentesting':'PENTEST'}.get(page)
    return render_template('soc/page.html',page=page,page_title=PAGES[page],filters=filters,data=data,events=events,alerts=alerts,recommendations=recommendations(path,filters),summary_text=summary(path,filters),ips=ip_statistics(path),choices=choices,tool_records=tool_records(path,tool_type,filters) if tool_type else [],intelligence_records=intelligence_records(path),incidents=incidents(path),api_metrics=api_metrics(path),csrf_token=session.setdefault('soc_csrf',secrets.token_urlsafe(32)),now=datetime.now(timezone.utc).isoformat(),**extra)

@soc.route('/')
@admin_required
def dashboard():return _render('dashboard')
@soc.route('/analytics')
@admin_required
def analytics_page():return _render('analytics')
@soc.route('/ai-summary')
@admin_required
def ai_summary():return _render('ai_summary')
@soc.route('/ai-recommendations')
@admin_required
def ai_recommendations():return _render('recommendations')
@soc.route('/ai-agent',methods=['GET','POST'])
@admin_required
def ai_agent():
    question=request.form.get('question','') if request.method=='POST' else request.args.get('question','');answer=agent_answer(current_app.config['DATABASE'],question) if question else None
    return _render('agent',question=question,answer=answer)
@soc.route('/ai-copilot',methods=['GET','POST'])
@admin_required
def copilot():
    question=request.form.get('question','') if request.method=='POST' else ''
    answer=copilot_answer(current_app.config['DATABASE'],question,agent_answer(current_app.config['DATABASE'],question)) if question else None
    return _render('copilot',question=question,answer=answer)
def _persist_analysis(page, finding_type, source, result, ip_address=None):
    stored=persist_finding(current_app.config['DATABASE'],finding_type,source,result,session['admin_id'],ip_address=ip_address)
    flash(f"{page} saved as security event {stored['event_id']}"+(f" and correlated incident #{stored['incident_id']}." if stored['incident_id'] else '.'),'success')
    return stored
@soc.route('/url-analysis',methods=['GET','POST'])
@admin_required
def url_analysis():
    result=None
    if request.method=='POST':
        try: result=analyse_url(request.form.get('url'));_persist_analysis('URL local analysis','URL_ANALYSIS','URL_ANALYZER',result)
        except ValueError as exc: flash(str(exc),'error')
    return _render('url_analysis',result=result)
@soc.route('/email-security',methods=['GET','POST'])
@admin_required
def email_security():
    result=None
    if request.method=='POST':
        try:
            result=analyse_email(request.form.get('subject'),request.form.get('sender'),request.form.get('recipient'),request.form.get('body'),request.form.get('headers'),current_app.config['DATABASE']);_persist_analysis('Email local analysis','EMAIL_ANALYSIS','EMAIL_ANALYZER',result)
        except ValueError as exc: flash(str(exc),'error')
    return _render('email_security',result=result)
def _uploaded_analysis(page, finding_type, source, analyzer):
    result=None
    if request.method=='POST':
        upload=request.files.get('analysis_file')
        try:
            if not upload or not upload.filename: raise ValueError('Select a file to analyse.')
            result=analyzer(upload.read(3*1024*1024+1),secure_filename(upload.filename));_persist_analysis(page,finding_type,source,result)
        except ValueError as exc: flash(str(exc),'error')
    return _render(page,result=result)
@soc.route('/image-phishing',methods=['GET','POST'])
@admin_required
def image_phishing(): return _uploaded_analysis('image_phishing','IMAGE_ANALYSIS','IMAGE_ANALYZER',analyse_image)
@soc.route('/qr-security',methods=['GET','POST'])
@admin_required
def qr_security(): return _uploaded_analysis('qr_security','QR_ANALYSIS','QR_ANALYZER',analyse_qr)
@soc.route('/nmap-analysis',methods=['GET','POST'])
@admin_required
def nmap(): return _uploaded_analysis('nmap','NMAP','NMAP_IMPORTED_XML',lambda data,name:parse_nmap_xml(data))
@soc.route('/wireshark-analysis',methods=['GET','POST'])
@admin_required
def wireshark(): return _uploaded_analysis('wireshark','WIRESHARK','UPLOADED_PACKET_CAPTURE',lambda data,name:analyse_pcap(data))
@soc.route('/ip-intelligence',methods=['GET','POST'])
@admin_required
def ip_intelligence():
    result=None
    if request.method=='POST':
        try:
            result=analyse_ip(request.form.get('ip_address'),current_app.config['DATABASE']);_persist_analysis('IP local analysis','IP_INTELLIGENCE','IP_INTELLIGENCE',result,ip_address=result['target'])
        except ValueError as exc: flash(str(exc),'error')
    return _render('ip_intelligence',result=result)
@soc.route('/virustotal-intelligence',methods=['GET','POST'])
@admin_required
def virustotal():
    result=None
    if request.method=='POST':
        value=request.form.get('target','').strip()
        try:
            result=analyse_url(value,external=True) if value.startswith(('http://','https://')) else analyse_ip(value,current_app.config['DATABASE'],external=True)
            _persist_analysis('Threat-intelligence lookup','VIRUSTOTAL','VIRUSTOTAL',result,ip_address=result['target'] if result.get('ip_type') else None)
        except ValueError as exc: flash('Enter a valid URL or IP address.','error')
    return _render('virustotal',result=result)
@soc.route('/reports',methods=['GET','POST'])
@admin_required
def reports():
    report=None
    if request.method=='POST':
        try: report=generate_report(current_app.config['DATABASE'],request.form.get('report_type','Threat Report'),int(request.form['security_event_id']),session['admin_id']);flash('Database-backed security report generated.','success')
        except (ValueError,KeyError): flash('Select a valid security event.','error')
    return _render('reports',report=report)
@soc.route('/active-threats')
@admin_required
def active_threats():return _render('active_threats')
@soc.route('/threat-investigation')
@admin_required
def investigations():return _render('investigations')
@soc.route('/threat-investigation/<int:record_id>')
@admin_required
def investigation_detail(record_id):
    detail=event_detail(current_app.config['DATABASE'],record_id)
    if not detail:flash('Security record was not found.','error');return redirect(url_for('soc.investigations'))
    return _render('investigations',detail=detail)
@soc.route('/incident/<int:record_id>/action',methods=['POST'])
@admin_required
def incident_action(record_id):
    try:record_action(current_app.config['DATABASE'],record_id,request.form.get('action',''),request.form.get('note',''),session['admin_id']);flash('Analyst action recorded.','success')
    except ValueError as exc:flash(str(exc),'error')
    return redirect(url_for('soc.investigation_detail',record_id=record_id))
@soc.route('/risk-mitigation')
@admin_required
def mitigation():return _render('mitigation')
@soc.route('/siem-monitoring')
@admin_required
def siem():return _render('siem')
@soc.route('/security-events')
@admin_required
def events():return _render('events')
@soc.route('/live-api')
@admin_required
def live_api():return _render('live_api')
@soc.route('/rest-api')
@admin_required
def rest_api():return _render('rest_api')
@soc.route('/statistics')
@admin_required
def statistics():return _render('statistics')
@soc.route('/network-intelligence')
@admin_required
def network_intelligence():return _render('network_intelligence')
@soc.route('/vulnerability-assessment',methods=['GET','POST'])
@admin_required
def vulnerabilities():
    if request.method=='POST':
        try:
            add_tool_record(current_app.config['DATABASE'],'VULNERABILITY',request.form)
            risk=int(request.form.get('risk_score') or 0);result={'target':request.form.get('asset'),'risk_score':risk,'severity':request.form.get('severity','LOW'),'classification':request.form.get('title'),'recommendation':request.form.get('recommendation') or 'Review and remediate the recorded vulnerability.','indicators':[request.form.get('description') or 'Manual analyst finding.'],'reasons':['Manual assessment record.'],'confidence':1.0,'analysis_mode':request.form.get('source','MANUAL ENTRY')}
            _persist_analysis('Vulnerability finding','VULNERABILITY_ASSESSMENT',request.form.get('source','MANUAL'),result);flash('Vulnerability record saved and linked to the security-event workflow.','success')
        except ValueError as exc:flash(str(exc),'error')
    return _render('vulnerabilities')
@soc.route('/penetration-testing',methods=['GET','POST'])
@admin_required
def pentesting():
    if request.method=='POST':
        try:
            add_tool_record(current_app.config['DATABASE'],'PENTEST',request.form)
            risk=int(request.form.get('risk_score') or 0);result={'target':request.form.get('asset'),'risk_score':risk,'severity':request.form.get('severity','LOW'),'classification':request.form.get('title'),'recommendation':request.form.get('recommendation') or 'Review the approved test finding.','indicators':[request.form.get('description') or 'Manual authorised test finding.'],'reasons':['Test source: '+request.form.get('source','MANUAL ENTRY')],'confidence':1.0,'analysis_mode':request.form.get('source','MANUAL ENTRY')}
            _persist_analysis('Penetration-test finding','PENTEST',request.form.get('source','MANUAL'),result);flash('Authorized test record saved and linked to the security-event workflow.','success')
        except ValueError as exc:flash(str(exc),'error')
    return _render('pentesting')
@soc.route('/web-application-security')
@admin_required
def web_security():return _render('web_security')
@soc.route('/digital-forensics',methods=['GET','POST'])
@admin_required
def forensics():
    if request.method=='POST':
        try:forensic_case(current_app.config['DATABASE'],int(request.form['security_event_id']),session['admin_id'],request.form.get('conclusion',''),request.form.get('evidence_references',''));flash('Forensic case saved.','success')
        except (KeyError,ValueError):flash('Select a valid security event.','error')
    return _render('forensics')
@soc.route('/api-keys')
@admin_required
def api_keys():return _render('api_keys')
@soc.route('/settings',methods=['GET','POST'])
@admin_required
def settings():
    if request.method=='POST':
        from security_pjs.dashboard_data import _con
        con=_con(current_app.config['DATABASE']);now=datetime.now(timezone.utc).isoformat()
        try:
            for key in ('refresh_interval','working_hours','alert_preference','retention_days','failed_login_suspicious','failed_login_critical','failed_login_window_minutes','download_threshold','workday_start','workday_end','detection_sensitivity'):
                if request.form.get(key):con.execute('INSERT OR REPLACE INTO security_settings(setting_key,setting_value,updated_at) VALUES(?,?,?)',(key,request.form[key][:100],now))
            con.commit();flash('Security dashboard settings saved.','success')
        finally:con.close()
    return _render('settings')
@soc.route('/static-data',methods=['GET','POST'])
@admin_required
def static_data():
    imported=skipped=0;errors=[]
    if request.method=='POST':
        upload=request.files.get('security_file');name=(upload.filename or '').lower() if upload else ''
        if not upload or not name.endswith(('.json','.csv')):flash('Upload a JSON or CSV security-event file.','error');return _render('static_data')
        try:
            content=upload.read(1024*1024).decode('utf-8-sig');rows=json.loads(content) if name.endswith('.json') else list(csv.DictReader(io.StringIO(content)));rows=rows if isinstance(rows,list) else [rows]
            for row in rows[:200]:
                try:
                    event=normalize_event(row);process_event(current_app.config['DATABASE'],event,already_normalized=True);imported+=1
                except Exception as exc:skipped+=1;errors.append(str(exc))
            from security_pjs.dashboard_data import _con
            con=_con(current_app.config['DATABASE'])
            try:con.execute('INSERT INTO security_import_audit(filename,source_format,imported_count,skipped_count,created_at) VALUES(?,?,?,?,?)',(name,'JSON' if name.endswith('.json') else 'CSV',imported,skipped,datetime.now(timezone.utc).isoformat()));con.commit()
            finally:con.close()
            flash(f'Imported {imported} events; skipped {skipped} invalid rows.','success' if imported else 'error')
        except (UnicodeDecodeError,json.JSONDecodeError,csv.Error) as exc:flash(f'Could not parse uploaded security data: {exc}','error')
    return _render('static_data',imported=imported,skipped=skipped,import_errors=errors[:3])
