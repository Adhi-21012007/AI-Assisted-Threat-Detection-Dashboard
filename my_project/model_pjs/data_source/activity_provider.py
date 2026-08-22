"""Database/API-neutral activity source adapters for near-real-time inference."""
from abc import ABC,abstractmethod
from pathlib import Path
import sqlite3,json

class ActivityProvider(ABC):
    @abstractmethod
    def fetch_activities(self, limit=100): """Return dictionaries accepted by predict_activity."""

class JsonActivityProvider(ActivityProvider):
    def __init__(self,path):self.path=Path(path)
    def fetch_activities(self,limit=100):
        data=json.loads(self.path.read_text());return (data if isinstance(data,list) else [data])[-limit:]

class SQLiteActivityProvider(ActivityProvider):
    """Development adapter for the existing company.db activity_logs table."""
    def __init__(self,database_path):self.database_path=Path(database_path)
    def fetch_activities(self,limit=100):
        con=sqlite3.connect(self.database_path);con.row_factory=sqlite3.Row
        query="""SELECT l.user_id, l.user_type, l.activity_type, l.timestamp, l.ip_address, e.department, t.name AS team
                 FROM activity_logs l LEFT JOIN employees e ON e.employee_id=l.employee_id
                 LEFT JOIN teams t ON t.id=e.team_id ORDER BY l.id DESC LIMIT ?"""
        result=[]
        for row in con.execute(query,(limit,)):
            activity=dict(row);kind=(activity.get('activity_type') or '').lower();activity.update({'user_id':activity.pop('user_id') or 'UNKNOWN','user_role':'Admin' if activity.get('user_type')=='Admin' else 'Employee','source':'SQLite Activity Log','failed_login_count':1 if 'failed login' in kind else 0,'login_count':1 if 'login' in kind else 0,'task_activity_count':1 if 'task' in kind else 0,'ticket_count':1 if 'ticket' in kind else 0,'notification_activity_count':1 if 'notification' in kind else 0})
            result.append(activity)
        con.close();return result
