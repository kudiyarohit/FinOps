from flask import Blueprint, request, jsonify
from models import AwsAccount
from db import db
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

aws_routes = Blueprint("aws", __name__)
SECRET_KEY = os.getenv("SECRET_KEY")


def get_user_from_token(req):
    auth_header = req.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return int(decoded["sub"])
    except Exception as e:
        print("JWT ERROR:", e)
        return None


@aws_routes.route("/accounts", methods=["GET"])
def get_accounts():
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    accounts = AwsAccount.query.filter_by(user_id=user_id).all()
    result = []
    for acc in accounts:
        result.append({
            "id": acc.id,
            "account_name": acc.account_name,
            "region": acc.region,
            # ✅ Auto scan info bhi bhejo frontend ke liye
            "auto_scan_enabled": acc.auto_scan_enabled,
            "scan_interval_min": acc.scan_interval_min,
            "next_scan_at": acc.next_scan_at.isoformat() if acc.next_scan_at else None
        })
    return jsonify({"accounts": result}), 200


@aws_routes.route("/add-account", methods=["POST"])
def add_account():
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    account_name = data.get("account_name")
    role_arn = data.get("role_arn")
    region = data.get("region")

    if not account_name or not role_arn or not region:
        return jsonify({"message": "All fields are required"}), 400

    existing = AwsAccount.query.filter_by(
        user_id=user_id,
        role_arn=role_arn
    ).first()

    if existing:
        return jsonify({"message": "AWS account already added"}), 400

    new_account = AwsAccount(
        user_id=user_id,
        account_name=account_name,
        role_arn=role_arn,
        region=region
    )
    db.session.add(new_account)
    db.session.commit()

    return jsonify({
        "message": "✅ AWS account connected successfully",
        "account": {"account_name": account_name, "region": region}
    }), 200


@aws_routes.route("/delete-account/<int:account_id>", methods=["DELETE"])
def delete_account(account_id):
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    account = AwsAccount.query.filter_by(
        id=account_id,
        user_id=user_id
    ).first()

    if not account:
        return jsonify({"message": "Account not found"}), 404

    db.session.delete(account)
    db.session.commit()
    return jsonify({"message": "✅ AWS account deleted successfully"}), 200


# ✅ NAYA ROUTE — Auto scan enable/disable
@aws_routes.route("/set-auto-scan/<int:account_id>", methods=["POST"])
def set_auto_scan(account_id):
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    enabled = data.get("enabled", False)
    interval_min = data.get("interval_min")

    if enabled and (not interval_min or int(interval_min) < 1):
        return jsonify({"message": "Valid interval_min required"}), 400

    account = AwsAccount.query.filter_by(
        id=account_id, user_id=user_id
    ).first()

    if not account:
        return jsonify({"message": "Account not found"}), 404

    account.auto_scan_enabled = enabled
    account.scan_interval_min = int(interval_min) if enabled else None
    account.next_scan_at = (
        datetime.utcnow() + timedelta(minutes=int(interval_min))
        if enabled else None
    )
    db.session.commit()

    return jsonify({
        "message": "✅ Auto scan updated",
        "enabled": enabled,
        "interval_min": account.scan_interval_min,
        "next_scan_at": account.next_scan_at.isoformat() if account.next_scan_at else None
    }), 200