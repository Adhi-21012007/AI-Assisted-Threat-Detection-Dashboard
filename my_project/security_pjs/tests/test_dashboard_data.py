import os
import sqlite3
import unittest
from security_pjs.dashboard_data import agent_answer, analytics, event_detail, get_events, record_action, recommendations
from security_pjs.event_processor import process_event
from security_pjs.tests.test_pipeline import event, make_db

class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.path=make_db()
        con=sqlite3.connect(self.path)
        for column in ('name TEXT','designation TEXT','status TEXT'):
            con.execute('ALTER TABLE employees ADD COLUMN '+column)
        con.execute("UPDATE employees SET name='Alex Morgan',designation='Security Engineer',status='Active' WHERE employee_id='EMP001'")
        con.execute("UPDATE employees SET name='Jordan Lee',designation='Designer',status='Active' WHERE employee_id='EMP002'")
        con.close()
        process_event(self.path,event('LOGIN_SUCCESS',timestamp='2026-08-14T11:00:00+00:00'),True)
        process_event(self.path,event('FILE_DOWNLOAD',timestamp='2026-08-14T12:00:00+00:00',ip_address='10.0.0.7',metadata={'download_count':120,'sensitive':True}),True)
    def tearDown(self):os.unlink(self.path)
    def test_dashboard_metrics_filters_and_investigation(self):
        data=analytics(self.path)
        self.assertEqual(data['metrics']['total_events'],2)
        self.assertEqual(len(data['funnel']),5)
        self.assertTrue(data['attacks'])
        filtered=get_events(self.path,{'employee_id':'EMP001'},'EVENT')
        self.assertEqual(len(filtered),2)
        detail=event_detail(self.path,filtered[0]['id'])
        self.assertEqual(detail['employee_id'],'EMP001')
        self.assertIn('timeline',detail)
        record_action(self.path,detail['id'],'START_INVESTIGATION','Reviewed evidence','admin')
        self.assertEqual(event_detail(self.path,detail['id'])['incident_status'],'INVESTIGATING')
    def test_grounded_assistant_and_recommendations(self):
        self.assertTrue(recommendations(self.path))
        self.assertIn('EMP001',agent_answer(self.path,'What happened to EMP001?'))
        self.assertIn('security events',agent_answer(self.path,'Summarize the security situation.'))

if __name__=='__main__':unittest.main(verbosity=2)
