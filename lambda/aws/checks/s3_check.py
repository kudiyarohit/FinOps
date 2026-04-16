def check_s3_buckets(session):

    s3 = session.client("s3")
    buckets = s3.list_buckets()

    findings = []

    for b in buckets["Buckets"]:
        bucket_name = b["Name"]

        is_public = False

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl["Grants"]:
                if grant.get("Grantee", {}).get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    is_public = True
        except:
            pass

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            if '"Principal": "*"' in policy["Policy"]:
                is_public = True
        except:
            pass

        try:
            block = s3.get_public_access_block(Bucket=bucket_name)
            if not block["PublicAccessBlockConfiguration"].get("BlockPublicPolicy", True):
                is_public = True
        except:
            pass

        if is_public:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "severity": "HIGH",
                "title": "Public S3 Bucket",
                "description": f"Bucket {bucket_name} is publicly accessible",
                "recommendation": "Enable Block Public Access",
                "category": "SECURITY"
            })

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "severity": "MEDIUM",
                "title": "Encryption Not Enabled",
                "description": f"Bucket {bucket_name} is not encrypted",
                "recommendation": "Enable encryption",
                "category": "SECURITY"
            })

        # Logging
        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in logging:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "severity": "LOW",
                    "title": "Logging Disabled",
                    "description": "Access logging not enabled",
                    "recommendation": "Enable logging",
                    "category": "SECURITY"
                })
        except:
            pass

        # Unused
        try:
            objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            if "Contents" not in objects:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "severity": "LOW",
                    "title": "Unused S3 Bucket",
                    "description": "Bucket is empty",
                    "recommendation": "Delete unused bucket",
                    "category": "COST"
                })
        except:
            pass

    return findings