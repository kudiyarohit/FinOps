from db import db
from datetime import datetime


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_verified = db.Column(db.Boolean, default=False)


class Otp(db.Model):
    __tablename__ = "otps"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AwsAccount(db.Model):
    __tablename__ = "aws_accounts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    account_name = db.Column(db.String(100))
    role_arn = db.Column(db.String(512))
    region = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ✅ AUTO SCAN COLUMNS
    auto_scan_enabled = db.Column(db.Boolean, default=False)
    scan_interval_min = db.Column(db.Integer, nullable=True)   # minutes mein
    next_scan_at = db.Column(db.DateTime, nullable=True)


class ScanSession(db.Model):
    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    account_id = db.Column(db.Integer, db.ForeignKey("aws_accounts.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="RUNNING")

    results = db.relationship("ScanResult", backref="session", lazy=True)


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    account_id = db.Column(db.Integer, db.ForeignKey("aws_accounts.id"))

    service = db.Column(db.String(50))
    resource = db.Column(db.String(512))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(512))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    category = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class GlobalScan(db.Model):
    __tablename__ = "global_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    total = db.Column(db.Integer)
    high = db.Column(db.Integer)
    medium = db.Column(db.Integer)
    low = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)