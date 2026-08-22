from pathlib import Path
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

CATEGORICAL = ["user_role", "department", "team"]
NUMERIC = ["account_age_days","login_count","failed_login_count","successful_login_count","failed_login_ratio","login_frequency","session_duration","concurrent_sessions","hour","day_of_week","weekend","unusual_hour","working_hours","activities_per_hour","activities_per_day","file_access_count","file_upload_count","file_download_count","ticket_count","task_activity_count","notification_activity_count","unique_ip_count","ip_change_frequency","new_ip_indicator","sensitive_file_access","privilege_change","unusual_resource_access","deviation_from_user_baseline","deviation_from_team_baseline","activity_spike","login_pattern_deviation"]
FEATURES = CATEGORICAL + NUMERIC

def build_pipeline():
    return ColumnTransformer([("categorical",OneHotEncoder(handle_unknown="ignore"),CATEGORICAL),("numeric",StandardScaler(),NUMERIC)],remainder="drop")

def save_pipeline(pipeline, path): joblib.dump(pipeline,Path(path))
