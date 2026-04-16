from flask import Flask, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import os

from db import db
from auth import auth_routes
from aws.aws_accounts import aws_routes
from aws.aws_scan_routes import aws_scan_routes
from scheduler import start_scheduler   # ✅ NAYA IMPORT

load_dotenv()

app = Flask(__name__)
CORS(app)

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", 3306)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 20,
}

db.init_app(app)

app.register_blueprint(auth_routes, url_prefix="/auth")
app.register_blueprint(aws_routes, url_prefix="/aws")
app.register_blueprint(aws_scan_routes, url_prefix="/aws")


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("auth/login.html")

@app.route("/signup")
def signup_page():
    return render_template("auth/signup.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard/dashboard.html")

@app.route("/verify-otp")
def verify_otp_page():
    return render_template("auth/verify_otp.html")

@app.route("/forgot-password")
def forgot_password_page():
    return render_template("auth/forgot_password.html")

@app.route("/verify-reset-otp")
def verify_reset_otp_page():
    return render_template("auth/verify_reset_otp.html")

@app.route("/reset-password")
def reset_password_page():
    return render_template("auth/reset_password.html")

@app.route("/accounts")
def accounts_page():
    return render_template("dashboard/accounts.html")

@app.route("/manual")
def manual_scan_page():
    return render_template("dashboard/manual_scan.html")

@app.route("/history")
def history_page():
    return render_template("dashboard/history.html")


if __name__ == "__main__":
    with app.app_context():
        from models import User, Otp, AwsAccount, ScanSession, ScanResult, GlobalScan
        db.create_all()

    start_scheduler(app)   # ✅ Scheduler start karo

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False   # ✅ ZAROORI — warna scheduler 2 baar start hoga
    )