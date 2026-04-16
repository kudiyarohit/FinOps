from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import boto3
import json

scheduler = BackgroundScheduler()


def run_auto_scans(app):
    with app.app_context():
        from models import AwsAccount, ScanSession, ScanResult, GlobalScan, User
        from email_utils import send_scan_email
        from db import db

        now = datetime.utcnow()

        due_accounts = AwsAccount.query.filter(
            AwsAccount.auto_scan_enabled == True,
            AwsAccount.next_scan_at <= now
        ).all()

        if not due_accounts:
            return

        print(f"[AutoScan] {len(due_accounts)} account(s) due for scan")

        for account in due_accounts:
            session_obj = None
            try:
                user = User.query.get(account.user_id)

                session_obj = ScanSession(
                    user_id=account.user_id,
                    account_id=account.id,
                    status="RUNNING"
                )
                db.session.add(session_obj)
                db.session.commit()

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

                if response.get("FunctionError"):
                    raise Exception(f"Lambda error: {payload.get('errorMessage', 'Unknown')}")

                if "body" in payload:
                    body = json.loads(payload["body"])
                    if body.get("error"):
                        raise Exception(body["error"])
                    findings = body.get("findings", [])
                else:
                    findings = []

                valid_findings = [f for f in findings if f.get("title")]

                for f in valid_findings:
                    result = ScanResult(
                        session_id=session_obj.id,
                        user_id=account.user_id,
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

                session_obj.status = "COMPLETED"

                # ✅ Agle scan ka time set karo
                account.next_scan_at = now + timedelta(minutes=account.scan_interval_min)
                db.session.commit()

                # ✅ Email sirf HIGH findings par
                high_count = sum(1 for f in valid_findings if f.get("severity") == "HIGH")
                if high_count > 0 and user:
                    try:
                        send_scan_email(user.email, valid_findings)
                    except Exception as e:
                        print(f"[AutoScan] Email error: {e}")

                print(f"[AutoScan] ✅ {account.account_name} → {len(valid_findings)} findings")

            except Exception as e:
                print(f"[AutoScan] ❌ {account.account_name}: {e}")
                if session_obj:
                    try:
                        session_obj.status = "FAILED"
                        db.session.commit()
                    except:
                        pass


def start_scheduler(app):
    scheduler.add_job(
        func=run_auto_scans,
        args=[app],
        trigger="interval",
        minutes=1,
        id="auto_scan_job",
        replace_existing=True
    )
    scheduler.start()
    print("[Scheduler] ✅ Auto scan scheduler started")