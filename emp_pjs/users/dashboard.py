from flask import Blueprint, render_template, request
from model import user_details

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