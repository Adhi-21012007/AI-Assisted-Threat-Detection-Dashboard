"""Shared SQLite data layer for the Employee and Admin portals.

This module deliberately contains no web routes. It makes the current portals
share one local company database and leaves a clean integration seam for a
future API/security service.
"""
import os
import sqlite3
from datetime import date, datetime, timedelta
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.environ.get("COMPANY_DATABASE_PATH", os.path.join(BASE_DIR, "company.db"))

def initialize_company_db(database_path=None):
    con = sqlite3.connect(database_path or DATABASE_PATH)
    con.execute("PRAGMA foreign_keys = ON")
    c = con.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS admins (admin_id TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, department TEXT, leader TEXT, description TEXT, status TEXT DEFAULT 'Active');
    CREATE TABLE IF NOT EXISTS employees (
      employee_id TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL,
      profile_photo TEXT, email TEXT, phone TEXT, department TEXT, designation TEXT,
      joining_date TEXT, role TEXT DEFAULT 'Employee', team_id INTEGER, manager TEXT,
      status TEXT DEFAULT 'Active', FOREIGN KEY(team_id) REFERENCES teams(id));
    CREATE TABLE IF NOT EXISTS team_members (id INTEGER PRIMARY KEY, team_id INTEGER NOT NULL, employee_id TEXT NOT NULL UNIQUE,
      FOREIGN KEY(team_id) REFERENCES teams(id), FOREIGN KEY(employee_id) REFERENCES employees(employee_id));
    CREATE TABLE IF NOT EXISTS attendance (id INTEGER PRIMARY KEY, employee_id TEXT NOT NULL, work_date TEXT NOT NULL,
      check_in TEXT, break_start TEXT, break_end TEXT, check_out TEXT, break_minutes INTEGER DEFAULT 0, status TEXT DEFAULT 'Present',
      UNIQUE(employee_id, work_date), FOREIGN KEY(employee_id) REFERENCES employees(employee_id));
    CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, title TEXT NOT NULL, employee_id TEXT, team_id INTEGER, deadline TEXT,
      priority TEXT DEFAULT 'Medium', status TEXT DEFAULT 'Pending', details TEXT, created_at TEXT, created_by TEXT DEFAULT 'Admin',
      FOREIGN KEY(employee_id) REFERENCES employees(employee_id), FOREIGN KEY(team_id) REFERENCES teams(id));
    CREATE TABLE IF NOT EXISTS calendar_events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, event_date TEXT, event_time TEXT, event_type TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY, employee_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT, description TEXT,
      priority TEXT DEFAULT 'Medium', attachment TEXT, status TEXT DEFAULT 'Open', admin_response TEXT, created_at TEXT, FOREIGN KEY(employee_id) REFERENCES employees(employee_id));
    CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, recipient TEXT NOT NULL, title TEXT NOT NULL, body TEXT, category TEXT, created_at TEXT,
      FOREIGN KEY(recipient) REFERENCES employees(employee_id));
    CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY, user_id TEXT, user_type TEXT, employee_id TEXT, activity_type TEXT NOT NULL,
      description TEXT, timestamp TEXT NOT NULL, ip_address TEXT);
    CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY, event_type TEXT, severity TEXT, description TEXT, timestamp TEXT, status TEXT DEFAULT 'Open');
    """)
    # Security-pipeline columns are additive and preserve earlier dashboard rows.
    from security_pjs.alert_manager import ensure_security_schema
    ensure_security_schema(con)
    from security_pjs.dashboard_data import ensure_soc_schema
    ensure_soc_schema(con)
    # Compatibility for databases created by earlier project versions.
    def ensure_columns(table, columns):
        existing = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns:
            if name not in existing: c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    ensure_columns("employees", [("password_hash", "TEXT"), ("profile_photo", "TEXT"), ("role", "TEXT DEFAULT 'Employee'"), ("manager", "TEXT"), ("status", "TEXT DEFAULT 'Active'")])
    ensure_columns("teams", [("description", "TEXT"), ("status", "TEXT DEFAULT 'Active'")])
    ensure_columns("attendance", [("status", "TEXT DEFAULT 'Present'")])
    ensure_columns("tasks", [("team_id", "INTEGER"), ("deadline", "TEXT"), ("priority", "TEXT DEFAULT 'Medium'"), ("details", "TEXT"), ("created_at", "TEXT"), ("created_by", "TEXT DEFAULT 'Admin'")])
    ensure_columns("tickets", [("attachment", "TEXT"), ("admin_response", "TEXT")])
    ensure_columns("notifications", [("recipient", "TEXT")])
    ensure_columns("activity_logs", [("user_id", "TEXT"), ("user_type", "TEXT")])
    ensure_columns("team_members", [("employee_id", "TEXT")])
    notification_columns = {r[1] for r in c.execute("PRAGMA table_info(notifications)")}
    if "employee_id" in notification_columns: c.execute("UPDATE notifications SET recipient=employee_id WHERE recipient IS NULL")
    c.execute("UPDATE activity_logs SET user_id=COALESCE(user_id,employee_id), user_type=COALESCE(user_type,'Employee')")
    member_columns = {r[1] for r in c.execute("PRAGMA table_info(team_members)")}
    if "name" in member_columns: c.execute("UPDATE team_members SET employee_id=(SELECT employee_id FROM employees WHERE employees.name=team_members.name) WHERE employee_id IS NULL")
    if not c.execute("SELECT 1 FROM admins WHERE admin_id='admin'").fetchone():
        c.execute("INSERT INTO admins VALUES(?,?,?)", ("admin", "System Administrator", generate_password_hash("admin@123")))
    # Earlier standalone demos did not store employee credentials in the same
    # table. Give migrated records a safe test credential until Admin replaces
    # them during normal account provisioning.
    c.execute("UPDATE employees SET password_hash=? WHERE password_hash IS NULL OR password_hash=''", (generate_password_hash("employee123"),))
    if not c.execute("SELECT 1 FROM employees").fetchone():
        c.executemany("INSERT INTO departments(name) VALUES(?)", [("Technology",), ("Operations",), ("People",)])
        c.executemany("INSERT INTO teams(name,department,leader,description,status) VALUES(?,?,?,?,?)", [
            ("Product Engineering", "Technology", "Priya Shah", "Secure product delivery and engineering excellence.", "Active"),
            ("Customer Operations", "Operations", "Nadia Khan", "Customer-facing operations and service reliability.", "Active")])
        employees = [
            ("EMP001", "Alex Morgan", "employee123", "alex@northstar.test", "+91 98765 43210", "Technology", "Software Engineer", "2023-06-12", "Employee", 1, "Priya Shah", "Active"),
            ("EMP002", "Jordan Lee", "employee234", "jordan@northstar.test", "+91 98765 43211", "Technology", "UX Designer", "2022-04-04", "Employee", 1, "Priya Shah", "Active"),
            ("EMP003", "Samir Patel", "employee345", "samir@northstar.test", "+91 98765 43212", "Technology", "QA Engineer", "2024-01-15", "Employee", 1, "Priya Shah", "Active"),
            ("EMP004", "Nadia Khan", "employee456", "nadia@northstar.test", "+91 98765 43213", "Operations", "Operations Associate", "2021-08-20", "Employee", 2, "Nadia Khan", "Active"),
            ("EMP005", "Riya Bose", "employee567", "riya@northstar.test", "+91 98765 43214", "People", "HR Specialist", "2023-11-03", "Employee", None, "Elena Park", "Active")]
        c.executemany("INSERT INTO employees(employee_id,name,password_hash,email,phone,department,designation,joining_date,role,team_id,manager,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", [(a,b,generate_password_hash(p),e,ph,dg,ds,j,r,t,m,s) for a,b,p,e,ph,dg,ds,j,r,t,m,s in employees])
        c.executemany("INSERT INTO team_members(team_id,employee_id) VALUES(?,?)", [(1,"EMP001"),(1,"EMP002"),(1,"EMP003"),(2,"EMP004")])
        today = date.today().isoformat(); now=datetime.now()
        c.executemany("INSERT INTO attendance(employee_id,work_date,check_in,break_start,break_end,break_minutes,status) VALUES(?,?,?,?,?,?,?)", [
            ("EMP001",today,now.replace(hour=9,minute=5).isoformat(timespec="seconds"),None,None,0,"Present"),
            ("EMP002",today,now.replace(hour=9,minute=0).isoformat(timespec="seconds"),None,None,0,"Present"),
            ("EMP003",today,now.replace(hour=9,minute=28).isoformat(timespec="seconds"),now.replace(hour=13,minute=0).isoformat(timespec="seconds"),None,0,"On Break"),
            ("EMP004",today,None,None,None,0,"Absent")])
        c.executemany("INSERT INTO tasks(title,employee_id,team_id,deadline,priority,status,details,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", [
            ("Complete UI accessibility pass","EMP001",1,(date.today()+timedelta(days=2)).isoformat(),"High","In Progress","Review product screens.",datetime.now().isoformat(),"Admin"),
            ("Validate release candidate","EMP003",1,(date.today()+timedelta(days=1)).isoformat(),"Medium","Pending","Execute regression suite.",datetime.now().isoformat(),"Admin")])
        c.executemany("INSERT INTO calendar_events(title,event_date,event_time,event_type,description) VALUES(?,?,?,?,?)", [("Leadership sync",today,"15:30","Meeting","Monthly operational update."),("Security awareness deadline",(date.today()+timedelta(days=2)).isoformat(),"17:00","Deadline","Required training completion."),("Independence Day","2026-08-15","","Holiday","Company holiday.")])
        c.execute("INSERT INTO tickets(employee_id,title,category,description,priority,status,created_at) VALUES(?,?,?,?,?,?,?)", ("EMP001","VPN access intermittently fails","IT Issue","Connection drops during secure gateway authentication.","High","Open",datetime.now().isoformat()))
        c.executemany("INSERT INTO notifications(recipient,title,body,category,created_at) VALUES(?,?,?,?,?)", [("EMP001","Welcome to Northstar","Your employee workspace is ready.","Company announcement",datetime.now().isoformat()),("EMP001","Timesheet reminder","Remember to check out at the end of your workday.","Attendance notification",datetime.now().isoformat())])
        c.executemany("INSERT INTO activity_logs(user_id,user_type,employee_id,activity_type,description,timestamp,ip_address) VALUES(?,?,?,?,?,?,?)", [("EMP001","Employee","EMP001","Login","Successful employee login",datetime.now().isoformat(),"127.0.0.1"),("EMP005","Employee","EMP005","Failed login","Invalid employee password",datetime.now().isoformat(),"127.0.0.1")])
        c.executemany("INSERT INTO security_events(event_type,severity,description,timestamp) VALUES(?,?,?,?)", [("Authentication anomaly","Medium","Repeated failed login recorded.",datetime.now().isoformat()),("Endpoint alert","High","Outdated endpoint agent detected.",datetime.now().isoformat())])
    con.commit(); con.close()
