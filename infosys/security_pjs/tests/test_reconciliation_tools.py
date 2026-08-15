import os
import sqlite3
import unittest
from security_pjs.dashboard_data import add_tool_record, api_metrics, tool_records
from security_pjs.event_processor import process_event
from security_pjs.reconcile_ai_results import reconcile
from security_pjs.tests.test_pipeline import event, make_db
from security_pjs.validate_security_data import validate

class ReconciliationAndToolTests(unittest.TestCase):
    def setUp(self):
        self.path=make_db();process_event(self.path,event('FILE_DOWNLOAD',timestamp='2026-08-14T12:00:00+00:00',metadata={'download_count':120,'sensitive':True}),True)
    def tearDown(self):os.unlink(self.path)
    def test_reconcile_and_validate_ai_data(self):
        con=sqlite3.connect(self.path);con.execute("UPDATE security_events SET risk_score=NULL,severity='INFO',ai_status='FAILED' WHERE record_type='EVENT'");con.commit();con.close()
        report=reconcile(self.path)
        self.assertEqual(report['failed'],0);self.assertEqual(report['reconciled'],1)
        self.assertEqual(validate(self.path)['invalid'],0)
    def test_analyst_tool_records_and_api_metrics(self):
        add_tool_record(self.path,'VULNERABILITY',{'asset':'employee-portal','title':'Validated finding','severity':'HIGH','risk_score':'75','status':'OPEN','recommendation':'Patch in approved change window'})
        self.assertEqual(tool_records(self.path,'VULNERABILITY')[0]['asset'],'employee-portal')
        con=sqlite3.connect(self.path);con.execute("INSERT INTO security_api_request_metrics(endpoint,method,status_code,duration_ms,created_at) VALUES('/api/security/health','GET',200,3.2,'2026-08-14T12:00:00+00:00')");con.commit();con.close()
        self.assertEqual(api_metrics(self.path)['requests'],1)

if __name__=='__main__':unittest.main(verbosity=2)
