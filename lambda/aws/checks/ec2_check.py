from datetime import datetime, timedelta


def check_ec2(session):

    ec2 = session.client("ec2")
    cloudwatch = session.client("cloudwatch")

    findings = []

    response = ec2.describe_instances()

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]
            state = instance["State"]["Name"]

            if state != "running":
                continue

            # 1. IDLE INSTANCE
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(minutes=30)

                metrics = cloudwatch.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=300,
                    Statistics=["Average"]
                )

                datapoints = metrics["Datapoints"]

                if datapoints:
                    avg_cpu = sum(d["Average"] for d in datapoints) / len(datapoints)

                    if avg_cpu < 5:
                        findings.append({
                            "service": "EC2",
                            "resource": instance_id,
                            "severity": "MEDIUM",
                            "title": "Idle EC2 Instance",
                            "description": f"Average CPU usage is {round(avg_cpu,2)}%",
                            "recommendation": "Stop or downsize the instance"
                        })
            except:
                pass

            # 2. OPEN PORT CHECK
            try:
                for sg in instance.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]

                    sg_data = ec2.describe_security_groups(GroupIds=[sg_id])

                    for perm in sg_data["SecurityGroups"][0]["IpPermissions"]:
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                findings.append({
                                    "service": "EC2",
                                    "resource": instance_id,
                                    "severity": "HIGH",
                                    "title": "Open Security Group",
                                    "description": f"Security group {sg_id} allows public access (0.0.0.0/0)",
                                    "recommendation": "Restrict inbound traffic"
                                })
            except:
                pass

            # 3. IAM ROLE CHECK
            if "IamInstanceProfile" not in instance:
                findings.append({
                    "service": "EC2",
                    "resource": instance_id,
                    "severity": "LOW",
                    "title": "No IAM Role Attached",
                    "description": "Instance does not have an IAM role",
                    "recommendation": "Attach a least-privilege IAM role"
                })

            # 4. UNENCRYPTED EBS
            try:
                for block in instance.get("BlockDeviceMappings", []):
                    volume_id = block["Ebs"]["VolumeId"]

                    vol = ec2.describe_volumes(VolumeIds=[volume_id])

                    encrypted = vol["Volumes"][0]["Encrypted"]

                    if not encrypted:
                        findings.append({
                            "service": "EC2",
                            "resource": instance_id,
                            "severity": "HIGH",
                            "title": "Unencrypted EBS Volume",
                            "description": f"Volume {volume_id} is not encrypted",
                            "recommendation": "Enable EBS encryption"
                        })
            except:
                pass

    # 5. UNUSED ELASTIC IP
    try:
        eips = ec2.describe_addresses()

        for eip in eips["Addresses"]:
            if "InstanceId" not in eip:
                findings.append({
                    "service": "EC2",
                    "resource": eip.get("PublicIp"),
                    "severity": "MEDIUM",
                    "title": "Unused Elastic IP",
                    "description": "Elastic IP is not attached to any instance",
                    "recommendation": "Release unused Elastic IP"
                })
    except:
        pass

    # 6. UNATTACHED EBS
    try:
        volumes = ec2.describe_volumes()

        for vol in volumes["Volumes"]:
            if vol["State"] == "available":
                findings.append({
                    "service": "EC2",
                    "resource": vol["VolumeId"],
                    "severity": "MEDIUM",
                    "title": "Unattached EBS Volume",
                    "description": "Volume is not attached to any instance",
                    "recommendation": "Delete unused volume"
                })
    except:
        pass

    return findings