def scan_vpc(session):

    ec2 = session.client("ec2")
    findings = []
    seen_sg = set()

    # SECURITY GROUP CHECK (DEDUP FIX)
    security_groups = ec2.describe_security_groups()["SecurityGroups"]

    for sg in security_groups:
        sg_id = sg["GroupId"]

        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":

                    if sg_id in seen_sg:
                        continue

                    seen_sg.add(sg_id)

                    findings.append({
                        "service": "VPC",
                        "resource": sg_id,
                        "severity": "HIGH",
                        "title": "Open Security Group",
                        "description": "Security group allows access from anywhere",
                        "recommendation": "Restrict access",
                        "category": "SECURITY"
                    })

    return findings