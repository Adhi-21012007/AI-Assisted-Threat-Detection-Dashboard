import sqlite3, os, sys
from datetime import datetime,date,timedelta
from functools import wraps
from flask import Flask,g,render_template,request,redirect,url_for,session,flash,send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from config import Config
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common_data import initialize_company_db
from security_pjs.event_processor import process_activity_log
from security_pjs.api import security_api
from soc import soc
app=Flask(__name__); app.config.from_object(Config); os.makedirs(app.config['UPLOAD_FOLDER'],exist_ok=True)
app.register_blueprint(security_api)
app.register_blueprint(soc)
def db():
 if 'db' not in g: g.db=sqlite3.connect(app.config['DATABASE']);g.db.row_factory=sqlite3.Row
 return g.db
@app.teardown_appcontext
def close(e):
 c=g.pop('db',None)
 if c:c.close()
def admin_required(f):
 @wraps(f)
 def w(*a,**k):
  if not session.get('admin_id'):return redirect(url_for('login'))
  return f(*a,**k)
 return w
def log(emp,kind,desc):
 cursor=db().execute('INSERT INTO activity_logs(user_id,user_type,employee_id,activity_type,description,timestamp,ip_address) VALUES(?,?,?,?,?,?,?)',(session.get('admin_id','admin'),'Admin',emp,kind,desc,datetime.now().isoformat(timespec='seconds'),request.remote_addr));db().commit()
 try: process_activity_log(app.config['DATABASE'],cursor.lastrowid)
 except Exception: app.logger.exception('Security pipeline failed for activity log %s',cursor.lastrowid)
def rows(q,p=()):return db().execute(q,p).fetchall()
def one(q,p=()):return db().execute(q,p).fetchone()
@app.route('/uploads/<path:filename>')
def uploaded_photo(filename): return send_from_directory(app.config['UPLOAD_FOLDER'],filename)
def init():
 initialize_company_db()
 return
 c=sqlite3.connect(app.config['DATABASE']).cursor();c.executescript('''
CREATE TABLE IF NOT EXISTS admins(admin_id TEXT PRIMARY KEY,name TEXT,password_hash TEXT);
CREATE TABLE IF NOT EXISTS departments(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY,name TEXT,department TEXT,leader TEXT,status TEXT DEFAULT 'Active');
CREATE TABLE IF NOT EXISTS employees(employee_id TEXT PRIMARY KEY,name TEXT,email TEXT,phone TEXT,department TEXT,designation TEXT,joining_date TEXT,team_id INTEGER,manager TEXT,status TEXT DEFAULT 'Active');
CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY,employee_id TEXT,work_date TEXT,check_in TEXT,break_start TEXT,break_end TEXT,check_out TEXT,break_minutes INTEGER DEFAULT 0,status TEXT DEFAULT 'Present');
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,title TEXT,employee_id TEXT,team_id INTEGER,deadline TEXT,priority TEXT,status TEXT DEFAULT 'Pending',details TEXT);
CREATE TABLE IF NOT EXISTS calendar_events(id INTEGER PRIMARY KEY,title TEXT,event_date TEXT,event_time TEXT,event_type TEXT,description TEXT);
CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY,employee_id TEXT,title TEXT,category TEXT,description TEXT,priority TEXT,status TEXT DEFAULT 'Open',admin_response TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,recipient TEXT,title TEXT,body TEXT,category TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS activity_logs(id INTEGER PRIMARY KEY,employee_id TEXT,activity_type TEXT,description TEXT,timestamp TEXT,ip_address TEXT);
CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY,event_type TEXT,severity TEXT,description TEXT,timestamp TEXT,status TEXT DEFAULT 'Open');
''')
 if not c.execute("SELECT 1 FROM admins WHERE admin_id='ADMIN001'").fetchone():
  c.execute('INSERT INTO admins VALUES(?,?,?)',('ADMIN001','Morgan Reed',generate_password_hash('admin123')))
  c.executemany('INSERT INTO departments(name) VALUES(?)',[('Technology',),('Operations',),('People',)])
  c.executemany('INSERT INTO teams(name,department,leader) VALUES(?,?,?)',[('Product Engineering','Technology','Priya Shah'),('Customer Operations','Operations','Ishaan Verma'),('People Experience','People','Elena Park')])
  emps=[('EMP001','Alex Morgan','alex@northstar.test','+91 98765 43210','Technology','Software Engineer','2023-06-12',1,'Priya Shah','Active'),('EMP002','Jordan Lee','jordan@northstar.test','+91 98765 43211','Technology','UX Designer','2022-04-04',1,'Priya Shah','Active'),('EMP003','Samir Patel','samir@northstar.test','+91 98765 43212','Technology','QA Engineer','2024-01-15',1,'Priya Shah','Active'),('EMP004','Nadia Khan','nadia@northstar.test','+91 98765 43213','Operations','Operations Associate','2021-08-20',2,'Ishaan Verma','Active'),('EMP005','Riya Bose','riya@northstar.test','+91 98765 43214','People','HR Specialist','2023-11-03',3,'Elena Park','Active')]
  c.executemany('INSERT INTO employees VALUES(?,?,?,?,?,?,?,?,?,?)',emps);today=date.today().isoformat()
  c.executemany('INSERT INTO attendance(employee_id,work_date,check_in,break_start,break_end,break_minutes,status) VALUES(?,?,?,?,?,?,?)',[('EMP001',today,datetime.now().replace(hour=9,minute=5).isoformat(timespec='seconds'),None,None,0,'Present'),('EMP002',today,datetime.now().replace(hour=9,minute=0).isoformat(timespec='seconds'),None,None,0,'Present'),('EMP003',today,datetime.now().replace(hour=9,minute=28).isoformat(timespec='seconds'),datetime.now().replace(hour=13,minute=0).isoformat(timespec='seconds'),None,0,'On Break'),('EMP004',today,None,None,None,0,'Absent')])
  c.executemany('INSERT INTO tasks(title,employee_id,team_id,deadline,priority,status,details) VALUES(?,?,?,?,?,?,?)',[('Complete UI accessibility pass','EMP001',1,(date.today()+timedelta(days=2)).isoformat(),'High','In Progress','Review product screens.'),('Validate release candidate','EMP003',1,(date.today()+timedelta(days=1)).isoformat(),'Medium','Pending','Execute regression suite.')])
  c.executemany('INSERT INTO calendar_events(title,event_date,event_time,event_type,description) VALUES(?,?,?,?,?)',[('Leadership sync',today,'15:30','Meeting','Monthly operational update.'),('Security awareness deadline',(date.today()+timedelta(days=2)).isoformat(),'17:00','Deadline','Required training completion.'),('Independence Day','2026-08-15','','Holiday','Company holiday.')])
  c.executemany('INSERT INTO tickets(employee_id,title,category,description,priority,status,created_at) VALUES(?,?,?,?,?,?,?)',[('EMP001','VPN access intermittently fails','IT Issue','Connection drops during secure gateway authentication.','High','Open',datetime.now().isoformat()),('EMP004','Attendance correction request','Attendance Correction','Please review the missed check-out from yesterday.','Medium','In Progress',datetime.now().isoformat())])
  c.executemany('INSERT INTO activity_logs(employee_id,activity_type,description,timestamp,ip_address) VALUES(?,?,?,?,?)',[('EMP001','Login','Successful employee login',datetime.now().isoformat(),'127.0.0.1'),('EMP003','Break start','Started a work break',datetime.now().isoformat(),'127.0.0.1'),('EMP002','Task completion','Completed research task',datetime.now().isoformat(),'127.0.0.1'),('EMP005','Failed login','Invalid employee password',datetime.now().isoformat(),'127.0.0.1')])
  c.executemany('INSERT INTO security_events(event_type,severity,description,timestamp) VALUES(?,?,?,?)',[('Authentication anomaly','Medium','Repeated failed login recorded for EMP005.',datetime.now().isoformat()),('Endpoint alert','High','Outdated endpoint agent detected on a managed device.',datetime.now().isoformat())])
 c.connection.commit();c.connection.close()
@app.route('/',methods=['GET','POST'])
def login():
 if session.get('admin_id'):return redirect(url_for('dashboard'))
 if request.method=='POST':
  a=one('SELECT * FROM admins WHERE admin_id=?',(request.form['admin_id'].strip(),))
  if a and check_password_hash(a['password_hash'],request.form['password']):session['admin_id']=a['admin_id'];log(a['admin_id'],'Admin login','Successful admin login');return redirect(url_for('dashboard'))
  flash('Invalid Admin ID or password.','error')
 return render_template('auth/login.html')
@app.route('/logout')
def logout():session.clear();return redirect(url_for('login'))
@app.route('/dashboard')
@admin_required
def dashboard():
 d=date.today().isoformat(); stats={'employees':one("SELECT count(*) n FROM employees WHERE status='Active'")['n'],'present':one("SELECT count(*) n FROM attendance WHERE work_date=? AND status='Present'",(d,))['n'],'breaks':one("SELECT count(*) n FROM attendance WHERE work_date=? AND status='On Break'",(d,))['n'],'tickets':one("SELECT count(*) n FROM tickets WHERE status IN ('Open','In Progress')")['n'],'teams':one("SELECT count(*) n FROM teams WHERE status='Active'")['n']};return render_template('admin/dashboard.html',stats=stats,activities=rows('SELECT l.*,e.name FROM activity_logs l LEFT JOIN employees e ON e.employee_id=l.employee_id ORDER BY l.id DESC LIMIT 6'),tickets=rows('SELECT t.*,e.name FROM tickets t JOIN employees e ON e.employee_id=t.employee_id ORDER BY t.id DESC LIMIT 5'),events=rows('SELECT * FROM calendar_events WHERE event_date>=? ORDER BY event_date LIMIT 4',(d,)),teams=rows('SELECT t.*,count(e.employee_id) members FROM teams t LEFT JOIN employees e ON e.team_id=t.id GROUP BY t.id'))
@app.route('/employees',methods=['GET','POST'])
@admin_required
def employees():
 if request.method=='POST':
  f=request.form; eid=f['employee_id'].upper(); photo=None; upload=request.files.get('profile_photo')
  if upload and upload.filename: photo=secure_filename(eid+'_'+upload.filename);upload.save(os.path.join(app.config['UPLOAD_FOLDER'],photo))
  db().execute('INSERT INTO employees(employee_id,name,password_hash,profile_photo,email,phone,department,designation,joining_date,role,team_id,manager,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(eid,f['name'],generate_password_hash(f['initial_password']),photo,f['email'],f['phone'],f['department'],f['designation'],f['joining_date'],f['role'],f.get('team_id') or None,f['manager'],f['status']))
  if f.get('team_id'): db().execute('INSERT OR REPLACE INTO team_members(team_id,employee_id) VALUES(?,?)',(f['team_id'],eid))
  db().commit();log(eid,'Employee created','Admin created employee account');flash('Employee created and login enabled.','success');return redirect(url_for('employees'))
 q=request.args.get('q','');return render_template('admin/employees.html',employees=rows("SELECT e.*,t.name team FROM employees e LEFT JOIN teams t ON t.id=e.team_id WHERE e.name LIKE ? OR e.employee_id LIKE ? ORDER BY e.name",('%'+q+'%','%'+q+'%')),teams=rows("SELECT * FROM teams WHERE status='Active'"),q=q)
@app.route('/employees/<eid>',methods=['GET','POST'])
@admin_required
def employee_profile(eid):
 e=one('SELECT e.*,t.name team FROM employees e LEFT JOIN teams t ON t.id=e.team_id WHERE e.employee_id=?',(eid,))
 if not e: return redirect(url_for('employees'))
 if request.method=='POST':
  f=request.form;db().execute('UPDATE employees SET name=?,email=?,phone=?,department=?,designation=?,team_id=?,manager=?,status=? WHERE employee_id=?',(f['name'],f['email'],f['phone'],f['department'],f['designation'],f.get('team_id') or None,f['manager'],f['status'],eid));db().execute('DELETE FROM team_members WHERE employee_id=?',(eid,));
  if f.get('team_id'): db().execute('INSERT INTO team_members(team_id,employee_id) VALUES(?,?)',(f['team_id'],eid))
  db().commit();log(eid,'Employee deactivated' if f['status']=='Inactive' else 'Employee edited','Admin updated employee profile and assignment');flash('Employee profile updated.','success');return redirect(url_for('employee_profile',eid=eid))
 attendance_rows=rows('SELECT * FROM attendance WHERE employee_id=? ORDER BY work_date DESC',(eid,)); task_rows=rows('SELECT * FROM tasks WHERE employee_id=? OR team_id=?',(eid,e['team_id'])); ticket_rows=rows('SELECT * FROM tickets WHERE employee_id=?',(eid,)); log_rows=rows('SELECT * FROM activity_logs WHERE employee_id=? ORDER BY id DESC',(eid,)); task_done=sum(x['status']=='Completed' for x in task_rows); ticket_resolved=sum(x['status']=='Resolved' for x in ticket_rows)
 return render_template('admin/employee_profile.html',employee=e,teams=rows('SELECT * FROM teams'),attendance=attendance_rows,tasks=task_rows,tickets=ticket_rows,logs=log_rows,task_done=task_done,ticket_resolved=ticket_resolved)
@app.route('/attendance',methods=['GET','POST'])
@admin_required
def attendance():
 if request.method=='POST':
  f=request.form; before=one('SELECT check_in,break_start,break_end,check_out FROM attendance WHERE id=?',(f['id'],));db().execute('UPDATE attendance SET check_in=?,break_start=?,break_end=?,check_out=?,break_minutes=?,status=? WHERE id=?',(f['check_in'] or None,f['break_start'] or None,f['break_end'] or None,f['check_out'] or None,f['break_minutes'] or 0,f['status'],f['id']));db().commit();description=f"Changed by {session['admin_id']}: check-in {before['check_in'] or '—'} → {f['check_in'] or '—'}. Reason: {f.get('reason') or 'Approved attendance correction'}";log(f['employee_id'],'Attendance corrected',description);flash('Attendance record corrected.','success');return redirect(url_for('attendance'))
 return render_template('admin/attendance.html',records=rows('SELECT a.*,e.name FROM attendance a JOIN employees e ON e.employee_id=a.employee_id ORDER BY a.work_date DESC,a.id DESC'))
@app.route('/teams',methods=['GET','POST'])
@admin_required
def teams():
 if request.method=='POST':
  f=request.form; leader=one('SELECT name FROM employees WHERE employee_id=?',(f['leader'],));cur=db().execute('INSERT INTO teams(name,department,leader,description,status) VALUES(?,?,?,?,?)',(f['name'],f['department'],leader['name'] if leader else '',f.get('description',''),f['status']));tid=cur.lastrowid
  for eid in set(request.form.getlist('members')+[f['leader']]):
   db().execute('UPDATE employees SET team_id=? WHERE employee_id=?',(tid,eid));db().execute('INSERT OR REPLACE INTO team_members(team_id,employee_id) VALUES(?,?)',(tid,eid))
  db().commit();log('', 'Team created','Admin created team: '+f['name']);flash('Team created and members assigned.','success');return redirect(url_for('teams'))
 return render_template('admin/teams.html',teams=rows('SELECT t.*,count(e.employee_id) members FROM teams t LEFT JOIN employees e ON e.team_id=t.id GROUP BY t.id'),employees=rows("SELECT * FROM employees WHERE status='Active'"))
@app.route('/tasks',methods=['GET','POST'])
@admin_required
def tasks():
 if request.method=='POST':
  f=request.form;db().execute('INSERT INTO tasks(title,employee_id,team_id,deadline,priority,status,details,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)',(f['title'],f.get('employee_id') or None,f.get('team_id') or None,f['deadline'],f['priority'],f['status'],f['details'],datetime.now().isoformat(),'Admin'));db().commit();log(f.get('employee_id',''),'Task created','Admin assigned task: '+f['title']);flash('Task assigned.','success');return redirect(url_for('tasks'))
 return render_template('admin/tasks.html',tasks=rows('SELECT x.*,e.name employee,t.name team FROM tasks x LEFT JOIN employees e ON e.employee_id=x.employee_id LEFT JOIN teams t ON t.id=x.team_id ORDER BY x.deadline'),employees=rows("SELECT * FROM employees WHERE status='Active'"),teams=rows("SELECT * FROM teams WHERE status='Active'"))
@app.route('/tasks/<int:task_id>/update', methods=['POST'])
@admin_required
def update_task(task_id):
 f=request.form; task=one('SELECT * FROM tasks WHERE id=?',(task_id,))
 if task:
  db().execute('UPDATE tasks SET status=?,priority=?,deadline=? WHERE id=?',(f['status'],f['priority'],f['deadline'],task_id));db().commit();log(task['employee_id'] or '', 'Task updated','Admin updated task: '+task['title']);flash('Task updated.','success')
 return redirect(url_for('tasks'))
@app.route('/calendar',methods=['GET','POST'])
@admin_required
def calendar():
 if request.method=='POST':
  f=request.form;db().execute('INSERT INTO calendar_events(title,event_date,event_time,event_type,description) VALUES(?,?,?,?,?)',(f['title'],f['event_date'],f['event_time'],f['event_type'],f['description']));db().commit();log('', 'Calendar event created','Admin published event: '+f['title']);flash('Calendar event published.','success');return redirect(url_for('calendar'))
 return render_template('admin/calendar.html',events=rows('SELECT * FROM calendar_events ORDER BY event_date,event_time'))
@app.route('/tickets',methods=['GET','POST'])
@admin_required
def tickets():
 if request.method=='POST':
  f=request.form;t=one('SELECT * FROM tickets WHERE id=?',(f['id'],));db().execute('UPDATE tickets SET status=?,priority=?,admin_response=? WHERE id=?',(f['status'],f['priority'],f['response'],f['id']));db().execute('INSERT INTO notifications(recipient,title,body,category,created_at) VALUES(?,?,?,?,?)',(t['employee_id'],'Ticket #'+f['id']+' updated','Your ticket status is now '+f['status']+'. '+(f['response'] or ''),'Ticket notification',datetime.now().isoformat()));db().commit();log(t['employee_id'],'Ticket updated','Admin updated ticket #'+f['id']);flash('Ticket updated and employee notified.','success');return redirect(url_for('tickets'))
 return render_template('admin/tickets.html',tickets=rows('SELECT t.*,e.name FROM tickets t JOIN employees e ON e.employee_id=t.employee_id ORDER BY t.id DESC'))
@app.route('/notifications',methods=['GET','POST'])
@admin_required
def notifications():
 if request.method=='POST':
  f=request.form;target=f['recipient']; recipients=rows("SELECT employee_id FROM employees WHERE status='Active'") if target=='ALL' else rows("SELECT employee_id FROM employees WHERE team_id=? AND status='Active'",(target.split(':',1)[1],)) if target.startswith('TEAM:') else rows('SELECT employee_id FROM employees WHERE employee_id=?',(target,));db().executemany('INSERT INTO notifications(recipient,title,body,category,created_at) VALUES(?,?,?,?,?)',[(r['employee_id'],f['title'],f['body'],f['category'],datetime.now().isoformat()) for r in recipients]);db().commit();log('', 'Notification sent','Admin sent '+f['category']+' to '+target);flash('Notification sent.','success');return redirect(url_for('notifications'))
 return render_template('admin/notifications.html',notifications=rows('SELECT * FROM notifications ORDER BY id DESC'),employees=rows("SELECT * FROM employees WHERE status='Active'"),teams=rows("SELECT * FROM teams WHERE status='Active'"))
@app.route('/logs')
@admin_required
def logs():
 q=request.args.get('q','');return render_template('admin/activity_logs.html',logs=rows("SELECT l.*,e.name FROM activity_logs l LEFT JOIN employees e ON e.employee_id=l.employee_id WHERE l.employee_id LIKE ? OR l.activity_type LIKE ? OR l.description LIKE ? ORDER BY l.id DESC",('%'+q+'%','%'+q+'%','%'+q+'%')),q=q)
@app.route('/security')
@admin_required
def security():return redirect(url_for('soc.dashboard'))
with app.app_context():init()
if __name__=='__main__':app.run(debug=app.config['ENVIRONMENT']=='development',port=5001)
