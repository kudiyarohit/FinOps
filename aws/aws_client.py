import boto3


def assume_role(role_arn, region):

    sts_client = boto3.client("sts")

    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cloudguard-session"
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region
    )