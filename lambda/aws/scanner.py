from aws.checks.ec2_check import check_ec2
from aws.checks.s3_check import check_s3_buckets
from aws.checks.vpc_scanner import scan_vpc   

def run_scan(session):

    findings = []

    try:
        ec2_findings = check_ec2(session)
        findings.extend(ec2_findings)
    except Exception as e:
        print("EC2 scan error:", e)


    try:
        s3_findings = check_s3_buckets(session)
        findings.extend(s3_findings)
    except Exception as e:
        print("S3 scan error:", e)


    try:
        vpc_findings = scan_vpc(session)
        findings.extend(vpc_findings)
    except Exception as e:
        print("VPC scan error:", e)

    return findings