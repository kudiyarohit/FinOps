import boto3
import json
from aws.scanner import run_scan

def lambda_handler(event, context):

    try:
        role_arn = event.get("role_arn")
        region = event.get("region")

        sts = boto3.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="cloudguard-session"
        )

        creds = assumed["Credentials"]

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region
        )

        findings = run_scan(session)

        valid_findings = [f for f in findings if f.get("title")]

        return {
            "statusCode": 200,
            "body": json.dumps({
                "findings": valid_findings
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e)
            })
        }