import os, sqlite3, sys
from datetime import date, datetime
from functools import wraps
from flask import Flask, flash, g, redirect, render_template, request, session, url_for, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from config import Config
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common_data import initialize_company_db
from security_pjs.event_processor import process_activity_log

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(exc):
    connection = g.pop("db", None)
    if connection: connection.close()
def log(action, description):
    if session.get("employee_id"):
        cursor=db().execute("INSERT INTO activity_logs(user_id,user_type,employee_id,activity_type,description,timestamp,ip_address) VALUES(?,?,?,?,?,?,?)", (session["employee_id"],"Employee",session["employee_id"],action,description,datetime.now().isoformat(timespec="seconds"),request.remote_addr)); db().commit()
        try: process_activity_log(app.config["DATABASE"], cursor.lastrowid)
        except Exception: app.logger.exception("Security pipeline failed for activity log %s", cursor.lastrowid)
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("employee_id"): return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
@app.route('/uploads/<path:filename>')
def uploaded_photo(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
def employee(): return db().execute("SELECT e.*, t.name team_name, t.leader, t.description FROM employees e LEFT JOIN teams t ON e.team_id=t.id WHERE e.employee_id=?", (session["employee_id"],)).fetchone()
def attendance(): return db().execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?", (session["employee_id"], date.today().isoformat())).fetchone()
def working_hours(a):
    if not a or not a["check_in"]: return "0h 00m"
    end = datetime.fromisoformat(a["check_out"]) if a["check_out"] else datetime.now()
    start = datetime.fromisoformat(a["check_in"]); breaks = a["break_minutes"] or 0
    minutes = max(0, int((end-start).total_seconds()//60)-breaks)
    return f"{minutes//60}h {minutes%60:02d}m"
def init_db():
    initialize_company_db()
@app.route('/', methods=['GET','POST'])
def login():
    if session.get('employee_id'): return redirect(url_for('dashboard'))
    if request.method=='POST':
        eid=request.form.get('employee_id','').upper().strip(); emp=db().execute('SELECT * FROM employees WHERE employee_id=?',(eid,)).fetchone()
        if emp and check_password_hash(emp['password_hash'],request.form.get('password','')):
            session['employee_id']=eid; log('Login','Successful employee login'); return redirect(url_for('dashboard'))
        cursor=db().execute("INSERT INTO activity_logs(user_id,user_type,employee_id,activity_type,description,timestamp,ip_address) VALUES(?,?,?,?,?,?,?)",(eid or 'UNKNOWN','Employee',eid or 'UNKNOWN','Failed login','Invalid credentials',datetime.now().isoformat(timespec='seconds'),request.remote_addr)); db().commit()
        try: process_activity_log(app.config["DATABASE"], cursor.lastrowid)
        except Exception: app.logger.exception("Security pipeline failed for activity log %s", cursor.lastrowid)
        flash('Invalid Employee ID or password.','error')
    return render_template('auth/login.html')
@app.route('/logout')
@login_required
def logout(): log('Logout','Employee signed out'); session.clear(); return redirect(url_for('login'))
@app.route('/dashboard')
@login_required
def dashboard():
    a=attendance(); d=db(); eid=session['employee_id']; all_tasks=d.execute("SELECT * FROM tasks WHERE employee_id=? OR team_id=(SELECT team_id FROM employees WHERE employee_id=?) ORDER BY status,id DESC",(eid,eid)).fetchall(); tickets=d.execute("SELECT * FROM tickets WHERE employee_id=? ORDER BY id DESC",(eid,)).fetchall(); history=d.execute("SELECT * FROM attendance WHERE employee_id=? ORDER BY work_date DESC LIMIT 7",(eid,)).fetchall(); return render_template('employee/dashboard.html', emp=employee(), att=a, hours=working_hours(a), tasks=all_tasks[:5], task_total=len(all_tasks), task_completed=sum(t['status']=='Completed' for t in all_tasks), tickets=tickets, attendance_history=history, activities=d.execute("SELECT * FROM activity_logs WHERE employee_id=? ORDER BY id DESC LIMIT 5",(eid,)).fetchall(), notifications=d.execute("SELECT * FROM notifications WHERE recipient=? ORDER BY id DESC LIMIT 4",(eid,)).fetchall(), events=d.execute("SELECT * FROM calendar_events WHERE event_date>=? ORDER BY event_date LIMIT 4",(date.today().isoformat(),)).fetchall(), today=date.today())
@app.route('/attendance', methods=['GET','POST'])
@login_required
def attendance_page():
    a=attendance()
    if request.method=='POST':
        action=request.form['action']; now=datetime.now().isoformat(timespec='seconds'); d=db()
        if action=='check_in' and not a: d.execute("INSERT INTO attendance(employee_id,work_date,check_in) VALUES(?,?,?)",(session['employee_id'],date.today().isoformat(),now)); log('Check-in','Checked in for work')
        elif action=='break_start' and a and not a['break_start']: d.execute("UPDATE attendance SET break_start=? WHERE id=?",(now,a['id'])); log('Break start','Started a break')
        elif action=='break_end' and a and a['break_start'] and not a['break_end']:
            mins=int((datetime.now()-datetime.fromisoformat(a['break_start'])).total_seconds()//60); d.execute("UPDATE attendance SET break_end=?, break_minutes=break_minutes+? WHERE id=?",(now,mins,a['id'])); log('Break end','Ended a break')
        elif action=='check_out' and a and not a['check_out'] and (not a['break_start'] or a['break_end']): d.execute("UPDATE attendance SET check_out=? WHERE id=?",(now,a['id'])); log('Check-out','Checked out for the day')
        else: flash('That attendance action is not available at this point.','error')
        d.commit(); return redirect(url_for('attendance_page'))
    return render_template('employee/attendance.html', emp=employee(), att=a, hours=working_hours(a))
@app.route('/profile')
@login_required
def profile():
    eid=session['employee_id']; d=db(); total=d.execute("SELECT count(*) n FROM tasks WHERE employee_id=? OR team_id=(SELECT team_id FROM employees WHERE employee_id=?)",(eid,eid)).fetchone()['n']; done=d.execute("SELECT count(*) n FROM tasks WHERE (employee_id=? OR team_id=(SELECT team_id FROM employees WHERE employee_id=?)) AND status='Completed'",(eid,eid)).fetchone()['n']; return render_template('employee/profile.html', emp=employee(), attendance_count=d.execute("SELECT count(*) n FROM attendance WHERE employee_id=? AND status='Present'",(eid,)).fetchone()['n'],task_total=total,task_done=done,tickets=d.execute("SELECT * FROM tickets WHERE employee_id=? ORDER BY id DESC",(eid,)).fetchall(),activities=d.execute("SELECT * FROM activity_logs WHERE employee_id=? ORDER BY id DESC LIMIT 5",(eid,)).fetchall())
@app.route('/tasks',methods=['GET','POST'])
@login_required
def tasks():
    d=db()
    if request.method=='POST': d.execute("INSERT INTO tasks(employee_id,title,details,created_at,created_by) VALUES(?,?,?,?,?)",(session['employee_id'],request.form['title'],request.form.get('details',''),datetime.now().isoformat(),'Employee')); d.commit(); log('Task creation','Created personal task: '+request.form['title']); return redirect(url_for('tasks'))
    eid=session['employee_id']; return render_template('employee/tasks.html', emp=employee(), tasks=d.execute("SELECT * FROM tasks WHERE employee_id=? OR team_id=(SELECT team_id FROM employees WHERE employee_id=?) ORDER BY status,id DESC",(eid,eid)).fetchall())
@app.route('/tasks/<int:id>/<action>')
@login_required
def task_action(id,action):
    d=db(); task=d.execute("SELECT * FROM tasks WHERE id=? AND (employee_id=? OR team_id=(SELECT team_id FROM employees WHERE employee_id=?))",(id,session['employee_id'],session['employee_id'])).fetchone()
    if task:
        if action=='complete': d.execute("UPDATE tasks SET status='Completed' WHERE id=?",(id,)); log('Task completion','Completed task: '+task['title'])
        elif action=='delete' and task['created_by']=='Employee': d.execute("DELETE FROM tasks WHERE id=?",(id,)); log('Task deletion','Deleted personal task: '+task['title'])
        d.commit()
    return redirect(url_for('tasks'))
@app.route('/calendar')
@login_required
def calendar(): log('Calendar interaction','Viewed company calendar'); return render_template('employee/calendar.html',emp=employee(),events=db().execute("SELECT * FROM calendar_events ORDER BY event_date,event_time").fetchall())
@app.route('/team')
@login_required
def team():
    e=employee(); return render_template('employee/team.html',emp=e,members=db().execute("SELECT e.* FROM team_members tm JOIN employees e ON e.employee_id=tm.employee_id WHERE tm.team_id=?",(e['team_id'],)).fetchall())
@app.route('/tickets',methods=['GET','POST'])
@login_required
def tickets():
    d=db()
    if request.method=='POST':
        attachment=None; file=request.files.get('attachment')
        if file and file.filename: attachment=secure_filename(file.filename); file.save(os.path.join(app.config['UPLOAD_FOLDER'],attachment))
        d.execute("INSERT INTO tickets(employee_id,title,category,description,priority,attachment,created_at) VALUES(?,?,?,?,?,?,?)",(session['employee_id'],request.form['title'],request.form['category'],request.form['description'],request.form['priority'],attachment,datetime.now().isoformat())); d.commit(); log('Ticket creation','Raised ticket: '+request.form['title']); flash('Ticket submitted to the Admin queue.','success'); return redirect(url_for('tickets'))
    return render_template('employee/tickets.html',emp=employee(),tickets=d.execute("SELECT * FROM tickets WHERE employee_id=? ORDER BY id DESC",(session['employee_id'],)).fetchall())
@app.route('/notifications')
@login_required
def notifications(): log('Notification viewed','Viewed notifications'); return render_template('employee/notifications.html',emp=employee(),notifications=db().execute("SELECT * FROM notifications WHERE recipient=? ORDER BY id DESC",(session['employee_id'],)).fetchall())
with app.app_context():
    init_db()

if __name__=='__main__':
    app.run(debug=app.config['ENVIRONMENT']=='development')
