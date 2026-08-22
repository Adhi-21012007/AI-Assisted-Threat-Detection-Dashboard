"""Convert raw activity windows or portal events into inference-ready features."""
from datetime import datetime
import pandas as pd
# Kept local so the inference-only ZIP does not need training modules.
FEATURES=["user_role","department","team","account_age_days","login_count","failed_login_count","successful_login_count","failed_login_ratio","login_frequency","session_duration","concurrent_sessions","hour","day_of_week","weekend","unusual_hour","working_hours","activities_per_hour","activities_per_day","file_access_count","file_upload_count","file_download_count","ticket_count","task_activity_count","notification_activity_count","unique_ip_count","ip_change_frequency","new_ip_indicator","sensitive_file_access","privilege_change","unusual_resource_access","deviation_from_user_baseline","deviation_from_team_baseline","activity_spike","login_pattern_deviation"]

DEFAULTS={"user_role":"Employee","department":"Unknown","team":"Unassigned","account_age_days":365,"login_count":1,"failed_login_count":0,"successful_login_count":1,"login_frequency":1.0,"session_duration":60.0,"concurrent_sessions":1,"hour":9,"day_of_week":0,"weekend":0,"activities_per_hour":2.0,"activities_per_day":8.0,"file_access_count":0,"file_upload_count":0,"file_download_count":0,"ticket_count":0,"task_activity_count":0,"notification_activity_count":0,"unique_ip_count":1,"ip_change_frequency":0.0,"new_ip_indicator":0,"sensitive_file_access":0,"privilege_change":0,"unusual_resource_access":0,"deviation_from_user_baseline":0.3,"deviation_from_team_baseline":0.3,"activity_spike":0,"login_pattern_deviation":0.3}

def build_feature_row(activity):
    row=DEFAULTS.copy();row.update({k:v for k,v in activity.items() if v is not None})
    timestamp=row.get('timestamp')
    if timestamp and ('hour' not in activity or 'day_of_week' not in activity):
        dt=datetime.fromisoformat(str(timestamp).replace('Z','+00:00'))
        if 'hour' not in activity: row['hour']=dt.hour
        if 'day_of_week' not in activity: row['day_of_week']=dt.weekday()
    row['weekend']=int(bool(row.get('weekend',row['day_of_week']>=5)));row['unusual_hour']=int(row['hour']<7 or row['hour']>20);row['working_hours']=int(8<=row['hour']<=18 and not row['weekend'])
    row['successful_login_count']=max(0,float(row.get('successful_login_count',row['login_count']-row['failed_login_count'])))
    row['failed_login_ratio']=float(row['failed_login_count'])/max(float(row['login_count']),1.0)
    return pd.DataFrame([{key:row[key] for key in FEATURES}])
