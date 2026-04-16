from datetime import datetime, timedelta


def scan_vpc(session):
    findings = []

    ec2 = session.client("ec2")

    # -----------------------------
    # 1. NAT GATEWAY CHECK
    # -----------------------------
    nat_gateways = ec2.describe_nat_gateways()["NatGateways"]

    if len(nat_gateways) > 0:
        for nat in nat_gateways:
            nat_id = nat["NatGatewayId"]

            findings.append({
                "service": "VPC",
                "resource": nat_id,
                "severity": "MEDIUM",
                "title": "NAT Gateway Running",
                "description": "NAT Gateway incurs hourly cost even if idle",
                "recommendation": "Delete NAT Gateway if not required or replace with NAT instance"
            })

        if len(nat_gateways) > 1:
            findings.append({
                "service": "VPC",
                "resource": "Multiple NAT Gateways",
                "severity": "MEDIUM",
                "title": "Multiple NAT Gateways Detected",
                "description": "Multiple NAT Gateways may increase cost unnecessarily",
                "recommendation": "Use one NAT Gateway per AZ or consolidate resources"
            })

    # -----------------------------
    # 2. PUBLIC IPv4 CHECK
    # -----------------------------
    addresses = ec2.describe_addresses()["Addresses"]

    if len(addresses) > 0:
        for addr in addresses:
            findings.append({
                "service": "VPC",
                "resource": addr.get("PublicIp", "Unknown IP"),
                "severity": "MEDIUM",
                "title": "Public IPv4 Address in Use",
                "description": "Public IPv4 addresses are chargeable",
                "recommendation": "Release unused Elastic IPs or switch to private networking"
            })

    # -----------------------------
    # 3. DEFAULT VPC CHECK
    # -----------------------------
    vpcs = ec2.describe_vpcs()["Vpcs"]

    for vpc in vpcs:
        if vpc.get("IsDefault"):
            findings.append({
                "service": "VPC",
                "resource": vpc["VpcId"],
                "severity": "LOW",
                "title": "Default VPC in Use",
                "description": "Default VPC lacks strict network segmentation",
                "recommendation": "Use custom VPC for better control and security"
            })

    # -----------------------------
    # 4. SECURITY GROUP CHECK
    # -----------------------------
    security_groups = ec2.describe_security_groups()["SecurityGroups"]

    for sg in security_groups:
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append({
                        "service": "VPC",
                        "resource": sg["GroupId"],
                        "severity": "HIGH",
                        "title": "Open Security Group",
                        "description": "Security group allows access from anywhere (0.0.0.0/0)",
                        "recommendation": "Restrict access to specific IP ranges"
                    })

    # -----------------------------
    # 5. INTERNET GATEWAY CHECK
    # -----------------------------
    igws = ec2.describe_internet_gateways()["InternetGateways"]

    for igw in igws:
        if len(igw.get("Attachments", [])) == 0:
            findings.append({
                "service": "VPC",
                "resource": igw["InternetGatewayId"],
                "severity": "LOW",
                "title": "Unused Internet Gateway",
                "description": "Internet Gateway is not attached to any VPC",
                "recommendation": "Delete unused Internet Gateway"
            })

    # -----------------------------
    # 6. NACL BASIC CHECK
    # -----------------------------
    nacls = ec2.describe_network_acls()["NetworkAcls"]

    for nacl in nacls:
        for entry in nacl.get("Entries", []):
            if entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("RuleAction") == "allow":
                findings.append({
                    "service": "VPC",
                    "resource": nacl["NetworkAclId"],
                    "severity": "MEDIUM",
                    "title": "Overly Permissive NACL",
                    "description": "Network ACL allows traffic from anywhere",
                    "recommendation": "Restrict NACL rules to specific IP ranges"
                })

    return findings