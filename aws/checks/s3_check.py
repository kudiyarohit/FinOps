def check_s3_buckets(session):

    s3 = session.client("s3")

    buckets = s3.list_buckets()

    findings = []

    for b in buckets["Buckets"]:

        bucket_name = b["Name"]

        # =========================
        # 1. PUBLIC ACCESS CHECK
        # =========================

        is_public = False

        # ACL CHECK
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)

            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})

                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    is_public = True
                    break
        except:
            pass

        # BUCKET POLICY CHECK (MOST IMPORTANT)
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy["Policy"]

            if '"Principal": "*"' in policy_str:
                is_public = True
        except:
            pass

        # BLOCK PUBLIC ACCESS CHECK
        try:
            block = s3.get_public_access_block(Bucket=bucket_name)

            config = block["PublicAccessBlockConfiguration"]

            if not config.get("BlockPublicPolicy", True):
                is_public = True
        except:
            pass

        if is_public:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "severity": "HIGH",
                "title": "Public S3 Bucket",
                "description": f"Bucket {bucket_name} is publicly accessible (ACL or policy)",
                "recommendation": "Enable Block Public Access and restrict bucket policy"
            })

        # =========================
        # 2. ENCRYPTION CHECK
        # =========================

        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "severity": "MEDIUM",
                "title": "Encryption Not Enabled",
                "description": f"Bucket {bucket_name} does not have encryption enabled",
                "recommendation": "Enable SSE-S3 or SSE-KMS encryption"
            })

        # =========================
        # 3. LOGGING CHECK
        # =========================

        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)

            if "LoggingEnabled" not in logging:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "severity": "LOW",
                    "title": "Logging Disabled",
                    "description": f"Access logging is not enabled for bucket {bucket_name}",
                    "recommendation": "Enable S3 access logging"
                })
        except:
            pass

        # =========================
        # 4. UNUSED BUCKET CHECK
        # =========================

        try:
            objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)

            if "Contents" not in objects:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "severity": "LOW",
                    "title": "Unused S3 Bucket",
                    "description": f"Bucket {bucket_name} appears to have no objects",
                    "recommendation": "Delete unused bucket to reduce cost"
                })
        except:
            pass

    return findings