from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import random
import os
from dotenv import load_dotenv

from models import User, Otp
from db import db
from email_utils import send_otp_email

load_dotenv()

auth_routes = Blueprint("auth", __name__)

SECRET_KEY = os.getenv("SECRET_KEY")


def generate_otp():
    return str(random.randint(100000, 999999))


@auth_routes.route("/signup", methods=["POST"])
def signup():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        if existing_user.is_verified:
            return jsonify({"message": "User already exists"}), 400
        else:
            
            otp_code = generate_otp()

            Otp.query.filter_by(email=email).delete()

            new_otp = Otp(email=email, otp=otp_code)
            db.session.add(new_otp)
            db.session.commit()

            send_otp_email(email, otp_code)

            return jsonify({"message": "OTP resent. Please verify"}), 200

    new_user = User(
        email=email,
        password=generate_password_hash(password),
        is_verified=False
    )

    db.session.add(new_user)
    db.session.commit()

    otp_code = generate_otp()

    new_otp = Otp(email=email, otp=otp_code)

    db.session.add(new_otp)
    db.session.commit()

    send_otp_email(email, otp_code)

    return jsonify({"message": "Signup successful. OTP sent to email"}), 201


@auth_routes.route("/verify-otp", methods=["POST"])
def verify_otp():

    data = request.get_json()

    email = data.get("email")
    otp = data.get("otp")

    from datetime import datetime, timedelta

    record = Otp.query.filter_by(email=email, otp=otp).first()

    if not record:
        return jsonify({"message": "Invalid OTP"}), 400

    if datetime.utcnow() - record.created_at > timedelta(minutes=5):
        return jsonify({"message": "OTP expired"}), 400

    user = User.query.filter_by(email=email).first()

    user.is_verified = True

    Otp.query.filter_by(email=email).delete()

    db.session.commit()

    return jsonify({"message": "Account verified"}), 200


@auth_routes.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials"}), 401

    if not user.is_verified:
        return jsonify({"message": "Verify email first"}), 403

    token = jwt.encode(
        {
            "sub": str(user.id),
            "email": str(user.email),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token
    }), 200

@auth_routes.route("/forgot-password", methods=["POST"])
def forgot_password():

    data = request.get_json()
    email = data.get("email")

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    otp_code = generate_otp()

    Otp.query.filter_by(email=email).delete()

    new_otp = Otp(email=email, otp=otp_code)
    db.session.add(new_otp)
    db.session.commit()

    send_otp_email(email, otp_code)

    return jsonify({"message": "OTP sent for password reset"}), 200

@auth_routes.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():

    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    from datetime import datetime, timedelta

    record = Otp.query.filter_by(email=email, otp=otp).first()

    if not record:
        return jsonify({"message": "Invalid OTP"}), 400

    if datetime.utcnow() - record.created_at > timedelta(minutes=5):
        return jsonify({"message": "OTP expired"}), 400
    
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    user.reset_verified = True
    db.session.commit()

    return jsonify({"message": "OTP verified"}), 200

@auth_routes.route("/reset-password", methods=["POST"])
def reset_password():

    data = request.get_json()
    email = data.get("email")
    new_password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    if not user.reset_verified:
        return jsonify({"message": "OTP not verified"}), 403

    user.reset_verified = False

    user.password = generate_password_hash(new_password)

    Otp.query.filter_by(email=email).delete()

    db.session.commit()

    return jsonify({"message": "Password reset successful"}), 200