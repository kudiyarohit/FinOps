from flask import Blueprint, request, jsonify
from aws.aws_accounts import get_user_from_token
from models import AwsAccount, User, ScanResult, ScanSession, GlobalScan
from email_utils import send_scan_email
from db import db
import os
from dotenv import load_dotenv
import boto3
import json

load_dotenv()

aws_scan_routes = Blueprint("aws_scan", __name__)
SECRET_KEY = os.getenv("SECRET_KEY")


# =========================================
# RUN SCAN
# =========================================
@aws_scan_routes.route("/scan/<int:account_id>", methods=["POST"])
def scan(account_id):

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    user = User.query.get(user_id)

    account = AwsAccount.query.filter_by(
        id=account_id,
        user_id=user_id
    ).first()

    if not account:
        return jsonify({"message": "Account not found"}), 404

    session_obj = None

    try:
        # ── CREATE SESSION ──────────────────────────
        session_obj = ScanSession(
            user_id=user_id,
            account_id=account.id,
            status="RUNNING"
        )
        db.session.add(session_obj)
        db.session.commit()

        # ── CALL LAMBDA ─────────────────────────────
        lambda_client = boto3.client("lambda", region_name="us-east-1")

        response = lambda_client.invoke(
            FunctionName="testFunction",
            InvocationType="RequestResponse",
            Payload=json.dumps({
                "role_arn": account.role_arn,
                "region": account.region
            })
        )

        payload = json.loads(response["Payload"].read())

# Lambda ka FunctionError check karo (timeout, crash, permission error)
        if response.get("FunctionError"):
            raise Exception(f"Lambda error: {payload.get('errorMessage', 'Unknown error')}")

        if "body" in payload:
            body = json.loads(payload["body"])
            if body.get("error"):
                raise Exception(f"Scan error: {body['error']}")
            findings = body.get("findings", [])
        else:
            findings = []

        valid_findings = [f for f in findings if f.get("title")]

        # ── SAVE FINDINGS ───────────────────────────
        for f in valid_findings:
            result = ScanResult(
                session_id=session_obj.id,
                user_id=user_id,
                account_id=account.id,
                service=f.get("service"),
                resource=f.get("resource"),
                severity=f.get("severity"),
                title=f.get("title"),
                description=f.get("description"),
                recommendation=f.get("recommendation"),
                category=f.get("category")
            )
            db.session.add(result)

        db.session.commit()

        # ── MARK COMPLETED ──────────────────────────
        session_obj.status = "COMPLETED"
        db.session.commit()

        # ── GLOBAL SNAPSHOT ─────────────────────────
        accounts = AwsAccount.query.filter_by(user_id=user_id).all()
        total = high = medium = low = 0

        for acc in accounts:
            last_session = ScanSession.query.filter_by(
                user_id=user_id,
                account_id=acc.id
            ).order_by(ScanSession.created_at.desc()).first()

            if not last_session:
                continue

            results = ScanResult.query.filter_by(session_id=last_session.id).all()

            for r in results:
                total += 1
                if r.severity == "HIGH":
                    high += 1
                elif r.severity == "MEDIUM":
                    medium += 1
                else:
                    low += 1

        snapshot = GlobalScan(
            user_id=user_id,
            total=total,
            high=high,
            medium=medium,
            low=low
        )
        db.session.add(snapshot)
        db.session.commit()

        # ── SUMMARY ─────────────────────────────────
        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in valid_findings:
            sev = f.get("severity", "LOW").upper()
            if sev in summary:
                summary[sev] += 1

        # ── EMAIL ALERT ─────────────────────────────
        if summary["HIGH"] > 0:
            try:
                send_scan_email(user.email, valid_findings)
            except Exception as e:
                print("EMAIL ERROR:", e)

        return jsonify({
            "status": "success",
            "summary": summary,
            "total": len(valid_findings),
            "session_id": session_obj.id,
            "findings": valid_findings
        })

    except Exception as e:
        if session_obj:
            try:
                session_obj.status = "FAILED"
                db.session.commit()
            except:
                pass

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================
# SCAN STATUS
# =========================================
@aws_scan_routes.route("/scan-status/<int:account_id>", methods=["GET"])
def scan_status(account_id):

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    last_session = ScanSession.query.filter_by(
        user_id=user_id,
        account_id=account_id
    ).order_by(ScanSession.created_at.desc()).first()

    if not last_session:
        return jsonify({"status": "NO_SCAN"})

    return jsonify({
        "status": last_session.status,
        "session_id": last_session.id
    })


# =========================================
# LAST SCAN
# =========================================
@aws_scan_routes.route("/last-scan/<int:account_id>", methods=["GET"])
def get_last_scan(account_id):

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    last_session = ScanSession.query.filter_by(
        user_id=user_id,
        account_id=account_id
    ).order_by(ScanSession.created_at.desc()).first()

    if not last_session:
        return jsonify({"findings": []})

    results = ScanResult.query.filter_by(session_id=last_session.id).all()

    findings = []
    for r in results:
        findings.append({
            "service": r.service,
            "resource": r.resource,
            "severity": r.severity,
            "title": r.title,
            "description": r.description,
            "recommendation": r.recommendation,
            "category": r.category,
            "timestamp": last_session.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({
        "session_id": last_session.id,
        "findings": findings
    })


# =========================================
# SCAN HISTORY
# =========================================
@aws_scan_routes.route("/scan-history/<int:account_id>", methods=["GET"])
def scan_history(account_id):

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    sessions = ScanSession.query.filter_by(
        user_id=user_id,
        account_id=account_id
    ).order_by(ScanSession.created_at.asc()).all()

    data = []
    for s in sessions:
        results = ScanResult.query.filter_by(session_id=s.id).all()

        high   = sum(1 for r in results if r.severity == "HIGH")
        medium = sum(1 for r in results if r.severity == "MEDIUM")
        low    = sum(1 for r in results if r.severity == "LOW")

        data.append({
            "session_id": s.id,
            "time": s.created_at.isoformat(),
            "display_time": s.created_at.strftime("%d %b %H:%M"),
            "high": high,
            "medium": medium,
            "low": low
        })

    return jsonify({"history": data})


# =========================================
# GLOBAL HISTORY
# =========================================
@aws_scan_routes.route("/global-history", methods=["GET"])
def global_history():

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    scans = GlobalScan.query.filter_by(user_id=user_id)\
        .order_by(GlobalScan.created_at.asc()).all()

    data = []
    for s in scans:
        data.append({
            "time": s.created_at.isoformat(),
            "high": s.high,
            "medium": s.medium,
            "low": s.low
        })

    return jsonify({"history": data})

# =========================================
# SESSION FINDINGS (History ke liye)
# =========================================
@aws_scan_routes.route("/scan-findings/<int:account_id>/<int:session_id>", methods=["GET"])
def get_session_findings(account_id, session_id):

    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    # Verify session belongs to this user + account
    session = ScanSession.query.filter_by(
        id=session_id,
        user_id=user_id,
        account_id=account_id
    ).first()

    if not session:
        return jsonify({"findings": []}), 404

    results = ScanResult.query.filter_by(session_id=session_id).all()

    findings = [{
        "service":        r.service,
        "resource":       r.resource,
        "severity":       r.severity,
        "title":          r.title,
        "description":    r.description,
        "recommendation": r.recommendation,
        "category":       r.category
    } for r in results]

    return jsonify({"findings": findings})