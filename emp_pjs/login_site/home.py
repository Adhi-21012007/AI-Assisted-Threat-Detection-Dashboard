from flask import Blueprint, render_template, request, redirect, url_for
from model import user_details
from users import dashboard
home_page = Blueprint('home_pages', __name__)

@home_page.route('/', methods = ['POST','GET'])
def login_page():
    if request.method == 'POST':
        empid = request.form['empid']
        password = request.form['password']

        user = {

            "empid" : empid,
            "password" : password
        }

        user_details.append(user)
        return redirect(url_for('users.dash_page'))
    return render_template('index.html')
