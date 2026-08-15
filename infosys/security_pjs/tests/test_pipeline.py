import os, sqlite3, tempfile, unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from flask import Flask
from security_pjs.alert_manager import ensure_security_schema
from security_pjs.event_normalizer import normalize_activity_log
from security_pjs.event_processor import process_event
from security_pjs.api import security_api

def make_db():
    fd,path=tempfile.mkstemp(suffix='.db');os.close(fd);con=sqlite3.connect(path)
    con.execute('CREATE TABLE teams(id INTEGER PRIMARY KEY,name TEXT)');con.execute("INSERT INTO teams VALUES(1,'Cyber Security')")
    con.execute('CREATE TABLE employees(employee_id TEXT PRIMARY KEY,department TEXT,joining_date TEXT,team_id INTEGER)');con.executemany("INSERT INTO employees VALUES(?,?,?,?)", [('EMP001','Technology','2024-01-01',1),('EMP002','Technology','2024-01-01',1)])
    con.execute('CREATE TABLE activity_logs(id INTEGER PRIMARY KEY,employee_id TEXT,user_id TEXT,user_type TEXT,activity_type TEXT,description TEXT,timestamp TEXT,ip_address TEXT)')
    ensure_security_schema(con);con.close();return path
def event(kind='LOGIN_SUCCESS', **changes):
    payload={'employee_id':'EMP001','event_type':kind,'timestamp':datetime.now(timezone.utc).isoformat(),'ip_address':None,'source':'test','status':'SUCCESS','metadata':{}};payload.update(changes);return payload

class PipelineTests(unittest.TestCase):
    def setUp(self):self.path=make_db()
    def tearDown(self):os.unlink(self.path)
    def test_normalization(self):
        result=normalize_activity_log({'id':3,'employee_id':'EMP001','user_type':'Employee','activity_type':'Failed login','description':'Invalid credentials','timestamp':'2026-08-14T10:00:00','ip_address':'127.0.0.1'})
        self.assertEqual(result['event_id'],'activity-3');self.assertEqual(result['event_type'],'LOGIN_FAILED');self.assertEqual(result['status'],'FAILED');self.assertEqual(result['metadata']['description'],'Invalid credentials')
    def test_firewall_rules(self):
        base=datetime.now(timezone.utc).replace(hour=11,minute=0,second=0,microsecond=0)
        self.assertEqual(process_event(self.path,event('LOGIN_SUCCESS',timestamp=base.isoformat()),True)['decision'],'NORMAL')
        for n in range(4):process_event(self.path,event('LOGIN_FAILED',timestamp=(base+timedelta(seconds=n)).isoformat()),True)
        fifth=process_event(self.path,event('LOGIN_FAILED',timestamp=(base+timedelta(seconds=5)).isoformat()),True)
        self.assertTrue(any(a['alert_type']=='SUSPICIOUS_LOGIN' for a in fifth['alerts']))
        for n in range(6,15):process_event(self.path,event('LOGIN_FAILED',timestamp=(base+timedelta(seconds=n)).isoformat()),True)
        critical=process_event(self.path,event('LOGIN_FAILED',timestamp=(base+timedelta(seconds=15)).isoformat()),True)
        self.assertTrue(any(a['alert_type']=='BRUTE_FORCE' for a in critical['alerts']))
        process_event(self.path,event('LOGIN_SUCCESS',employee_id='EMP002',timestamp=(base+timedelta(minutes=1)).isoformat(),ip_address='10.0.0.1'),True)
        new_ip=process_event(self.path,event('LOGIN_SUCCESS',employee_id='EMP002',timestamp=(base+timedelta(minutes=2)).isoformat(),ip_address='192.168.1.9'),True)
        self.assertTrue(any(a['triggered_rule']=='NEW_IP_LOGIN' for a in new_ip['alerts']))
        after_hours=process_event(self.path,event('LOGIN_SUCCESS',timestamp=(base.replace(hour=2,minute=0,second=0,microsecond=0)).isoformat()),True)
        self.assertTrue(any(a['alert_type']=='UNUSUAL_LOGIN_TIME' for a in after_hours['alerts']))
        download=process_event(self.path,event('FILE_DOWNLOAD',metadata={'download_count':55}),True)
        self.assertTrue(any(a['alert_type']=='POSSIBLE_DATA_EXFILTRATION' for a in download['alerts']))
        sensitive=process_event(self.path,event('SENSITIVE_FILE_ACCESS',metadata={'sensitive':True}),True)
        self.assertTrue(any(a['alert_type']=='SENSITIVE_FILE_ACCESS' for a in sensitive['alerts']))
        privilege=process_event(self.path,event('PRIVILEGE_CHANGE'),True)
        self.assertTrue(any(a['alert_type']=='PRIVILEGE_CHANGE' for a in privilege['alerts']))
    def test_api(self):
        app=Flask(__name__);app.config.update(DATABASE=self.path,TESTING=True);app.register_blueprint(security_api);client=app.test_client()
        self.assertEqual(client.get('/api/security/health').status_code,200)
        self.assertEqual(client.post('/api/security/events',json={'employee_id':'EMP001'}).status_code,400)
        self.assertEqual(client.post('/api/security/events',json=event('LOGIN_SUCCESS',employee_id='EMP-001')).status_code,400)
        invalid=client.post('/api/security/events',json={'employee_id':'EMP001','event_type':'BAD'})
        self.assertEqual(invalid.status_code,400)
        self.assertEqual(client.post('/api/security/events',json=event('LOGIN_SUCCESS',employee_id='EMP404')).status_code,404)
        self.assertEqual(client.post('/api/security/events',json=event('LOGIN_SUCCESS',timestamp='not-a-timestamp')).status_code,400)
        response=client.post('/api/security/events',json=event('LOGIN_FAILED'))
        self.assertEqual(response.status_code,201)
        with patch.dict(os.environ,{'SECURITY_API_KEY':'test-api-key'}):
            self.assertEqual(client.post('/api/security/events',json=event('LOGIN_SUCCESS')).status_code,401)
            self.assertEqual(client.post('/api/security/events',json=event('LOGIN_SUCCESS'),headers={'X-API-Key':'test-api-key'}).status_code,201)
        self.assertEqual(client.get('/api/security/events?employee_id=EMP001').status_code,200)
        posted=client.post('/api/security/alerts',json={'employee_id':'EMP001','alert_type':'TEST_ALERT','severity':'LOW','risk_score':10})
        self.assertEqual(posted.status_code,201);self.assertEqual(client.get('/api/security/alerts?severity=LOW').status_code,200)
        app.config['DATABASE']=os.path.join(self.path,'unavailable.db')
        self.assertEqual(client.get('/api/security/health').status_code,503)
    def test_ai_analysis_and_failure_handling(self):
        normal=process_event(self.path,event('LOGIN_SUCCESS',timestamp='2026-08-14T11:00:00+00:00'),True)
        self.assertEqual(normal['ai_result']['analysis_status'],'COMPLETE')
        self.assertIn(normal['ai_result']['prediction'],{'Normal','Suspicious','Threat'})
        self.assertTrue(0<=normal['ai_result']['risk_score']<=100)
        threat=process_event(self.path,event('FILE_DOWNLOAD',timestamp='2026-08-14T02:00:00+00:00',metadata={'download_count':120,'sensitive':True}),True)
        self.assertEqual(threat['ai_result']['analysis_status'],'COMPLETE')
        self.assertIn(threat['ai_result']['severity'],{'Low','Medium','High','Critical'})
        with patch('security_pjs.event_processor.analyze_event',side_effect=RuntimeError('model unavailable')):
            failed=process_event(self.path,event('TASK_CREATED',timestamp='2026-08-14T12:00:00+00:00'),True)
        self.assertEqual(failed['ai_result']['analysis_status'],'FAILED')
        con=sqlite3.connect(self.path);row=con.execute("SELECT ai_status FROM security_events WHERE event_id=?",(failed['event']['event_id'],)).fetchone();con.close();self.assertEqual(row[0],'FAILED')

if __name__=='__main__':unittest.main(verbosity=2)
