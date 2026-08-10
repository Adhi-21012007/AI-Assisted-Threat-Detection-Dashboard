from flask import Blueprint, render_template, request
from model import user_details, attendance_details, request_details

user_dashboard = Blueprint('users', __name__)

@user_dashboard.route('/welcome', methods=['GET','PUT'])
def dash_page():

    empid = user_details[-1]['empid']

    return render_template("user/dashboard.html", empid = empid)

@user_dashboard.route('/profile', methods = ['POST', 'GET', 'PUT'])
def view_profile():
    empid = user_details[-1]['empid']
    return render_template("user/profile.html", empid=empid,

        fullname="Kishore",

        email="kishore@company.com",

        department="Security Operations",

        designation="SOC Analyst",

        phone="+91 9876543210",

        location="Chennai")

@user_dashboard.route('/attendance', methods = ['POST', 'GET'])
def attendance_form():
    empid = user_details[-1]['empid']
    if request.method == 'POST':
        date = request.form['date']
        checkin = request.form['checkin']
        checkout = request.form['checkout']
        status = request.form['status']
        mode = request.form['mode']
        remarks = request.form['remarks']

        daily_attendance = {
           # 'empid' : empid,
            'date' : date,
            'checkin' : checkin,
            'checkout' : checkout,
            'status' : status,
            'mode' : mode,
            'remarks' : remarks
        }

        attendance_details.append(daily_attendance)

    return render_template("user/attendance.html", empid = empid)

@user_dashboard.route('/request', methods = ['POST','GET'])
def leave():
    empid = user_details[-1]['empid']
    fullname = user_details[-1]['empid']
    if request.method == 'post':
        leave_type = request.form['leave_type']
        days = request.form['days']
        from_date = request.form['from_date']
        to_date = request.form['to_date']
        reason = request.form['reason']
        remarks = reason.form['remarks']

        leave_request = {
            'leave_type' : leave_type,
            'days' : days,
            'from_date' : from_date,
            'to_date' : to_date,
            'reason' : reason,
            'remarks' : remarks
        }
        request_details.append(leave_request)
    return render_template('user/leave.html', empid = empid, fullname = fullname)

@user_dashboard.route('/notifications', methods = ['POST','GET'])
def notifications():
    return render_template('user/attendace.html')
