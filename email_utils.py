import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


def send_otp_email(receiver_email, otp):

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()

    server.login(EMAIL_USER, EMAIL_PASS)

    message = f"Subject: FinOps OTP\n\nYour OTP is {otp}"

    server.sendmail(EMAIL_USER, receiver_email, message)

    server.quit()

def send_scan_email(receiver_email, findings):

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()

    server.login(EMAIL_USER, EMAIL_PASS)

    # 🔥 Build email content
    body = "FinOps Scan Report\n\n"

    if not findings:
        body += "✅ No issues found"
    else:
        for f in findings:
            body += f"""
-------------------------
Service: {f['service']}
Severity: {f['severity']}
Issue: {f['title']}
Details: {f['description']}
Fix: {f['recommendation']}
-------------------------
"""

    message = f"Subject: FinOps Alert\n\n{body}"

    server.sendmail(EMAIL_USER, receiver_email, message)

    server.quit()