from flask import Flask
from login_site import home_page
from users.dashboard import user_dashboard

app = Flask(__name__)

app.register_blueprint(home_page, url_prefix='/')
app.register_blueprint(user_dashboard, url_prefix='/dashboard')

if __name__ == "__main__":
    app.run(debug=True)