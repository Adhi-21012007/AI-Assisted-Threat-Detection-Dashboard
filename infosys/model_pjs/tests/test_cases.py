from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from detection.predict import predict_activity

CASES=[
 ('Normal employee login',{'user_id':'EMP001','user_role':'Employee','department':'Technology','team':'Product Engineering','hour':10,'login_count':1,'failed_login_count':0,'activities_per_hour':4}),
 ('Three failed logins',{'user_id':'EMP002','hour':22,'login_count':5,'failed_login_count':3,'unique_ip_count':2,'new_ip_indicator':1,'activity_spike':1,'activities_per_hour':17}),
 ('Brute force',{'user_id':'EMP003','hour':2,'login_count':35,'failed_login_count':28,'login_frequency':48,'unique_ip_count':4,'new_ip_indicator':1,'activity_spike':1,'activities_per_hour':55,'deviation_from_user_baseline':4.8,'deviation_from_team_baseline':4.2,'login_pattern_deviation':5.0}),
 ('Normal work activity',{'user_id':'EMP004','hour':11,'activities_per_hour':6,'file_access_count':8,'file_download_count':2,'task_activity_count':3}),
 ('Possible exfiltration',{'user_id':'EMP005','hour':1,'login_count':7,'failed_login_count':1,'unique_ip_count':3,'new_ip_indicator':1,'activity_spike':1,'file_access_count':280,'file_download_count':210,'file_upload_count':25,'sensitive_file_access':1,'activities_per_hour':52,'deviation_from_user_baseline':4.6,'deviation_from_team_baseline':4.0,'login_pattern_deviation':4.2}),
 ('New IP and spike',{'user_id':'EMP006','hour':23,'login_count':8,'failed_login_count':4,'unique_ip_count':3,'new_ip_indicator':1,'activity_spike':1,'activities_per_hour':25}),]

def run():
 results=[]
 for name,payload in CASES:
  event=predict_activity(payload);results.append({'test_case':name,**event});print(f"{name}: {event['prediction']} | {event['threat_type']} | risk {event['risk_score']}")
 (ROOT/'outputs'/'manual_test_results.json').write_text(json.dumps(results,indent=2));return results
if __name__=='__main__':run()
