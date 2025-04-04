import json
import boto3
import csv
import io
import os
import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage
from ldap3 import Server, Connection, ALL, NTLM

# Fetch all WorkSpaces with pagination
def get_all_workspaces(client):
    all_workspaces = []
    next_token = None

    while True:
        kwargs = {}
        if next_token:
            kwargs['NextToken'] = next_token

        response = client.describe_workspaces(**kwargs)
        workspaces = response.get('Workspaces', [])
        all_workspaces.extend([ws for ws in workspaces if ws['State'] != 'TERMINATING'])

        next_token = response.get('NextToken')
        if not next_token:
            break

    return all_workspaces

def parse_user_account_control(uac):
    flags = {
        "SCRIPT":                      0x0001,
        "ACCOUNTDISABLE":             0x0002,
        "HOMEDIR_REQUIRED":           0x0008,
        "LOCKOUT":                    0x0010,
        "PASSWD_NOTREQD":             0x0020,
        "PASSWD_CANT_CHANGE":         0x0040,
        "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
        "TEMP_DUPLICATE_ACCOUNT":     0x0100,
        "NORMAL_ACCOUNT":             0x0200,
        "INTERDOMAIN_TRUST_ACCOUNT":  0x0800,
        "WORKSTATION_TRUST_ACCOUNT":  0x1000,
        "SERVER_TRUST_ACCOUNT":       0x2000,
        "DONT_EXPIRE_PASSWORD":       0x10000,
        "MNS_LOGON_ACCOUNT":          0x20000,
        "SMARTCARD_REQUIRED":         0x40000,
        "TRUSTED_FOR_DELEGATION":     0x80000,
        "NOT_DELEGATED":              0x100000,
        "USE_DES_KEY_ONLY":           0x200000,
        "DONT_REQUIRE_PREAUTH":       0x400000,
        "PASSWORD_EXPIRED":           0x800000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
        "PARTIAL_SECRETS_ACCOUNT":    0x04000000,
    }

    decoded_flags = [k for k, v in flags.items() if uac & v]
    enabled = not (uac & 0x0002)

    return {
        "Enabled": enabled,
        "Raw": uac,
        "Flags": ", ".join(decoded_flags)
    }

def lambda_handler(event, context):
    region = event.get('region', 'us-east-1')
    inactivity_days = int(event.get('inactivity_days', 60))

    secret_name = event.get('secret_name', 'ldap/service-account')
    
    s3_bucket = event['s3_bucket']    
    report_suffix = datetime.utcnow().strftime('%Y-%B')  # e.g., 2025-April
    s3_key = event.get('s3_key', f'workspaces/workspacesreport-{report_suffix}.csv')
    
    email_recipients = event.get('email_recipients', [])
    topic_arn = event.get('topic_arn', 'arn:aws:sns:us-east-1:067240469062:workspace-report-notification')
    topic_subject = event.get('topic_subject', 'Your WorkSpaces report is ready')

    # AWS Clients
    workspaces_client = boto3.client(
        'workspaces',
        region_name=region,
        endpoint_url='https://vpce-006efd501ac78c6f0-1vn811mk.workspaces.us-east-1.vpce.amazonaws.com'
    )
    cloudwatch_client = boto3.client(
        'cloudwatch',
        region_name=region,
        endpoint_url='https://vpce-0f0e60be8f16be755-pjmzpkj7.monitoring.us-east-1.vpce.amazonaws.com'
    )
    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        endpoint_url='https://vpce-06594f03bab06cb6c-43tj3453.ec2.us-east-1.vpce.amazonaws.com'
    )
    s3 = boto3.client(
        's3',
        region_name=region,
        endpoint_url='https://bucket.vpce-0c710cf50605b88a4-bmgrsqg9.s3.us-east-1.vpce.amazonaws.com'
    )
    sns = boto3.client(
        'sns',
        region_name=region,
        endpoint_url='https://vpce-005dcfed0fb7b48f1-ou4t236l.sns.us-east-1.vpce.amazonaws.com'
    )
    sm = boto3.client(
        'secretsmanager', 
        region_name=region,
        endpoint_url='https://vpce-0b4f1e3e765617702-hxwk0xnw.secretsmanager.us-east-1.vpce.amazonaws.com'
    )

    # Environment variables for LDAP connection
    ad_host = os.environ['AD_HOST']
    base_dn = os.environ['BASE_DN']

    # Get AD service account credentils from Secrets Manager
    secret_value = sm.get_secret_value(SecretId=secret_name)
    creds = json.loads(secret_value['SecretString'])
    ad_user = creds['username']
    ad_pass = creds['password']
 
    # LDAP Connection
    server = Server(ad_host, port=389, get_info=ALL)
    conn = Connection(server, user=ad_user, password=ad_pass, auto_bind=True)
    
    # Get WorkSpaces information
    workspaces = get_all_workspaces(workspaces_client)
    print(f"Found {len(workspaces)} workspaces")

    report_rows = []

    # Setup CloudWatch metrics parameters
    start_time = datetime.utcnow() - timedelta(days=inactivity_days)
    end_time = datetime.utcnow()
    period = 86400

    for ws in workspaces:
        try:
            workspace_id = ws['WorkspaceId']
            user_name = ws.get('UserName', '')
            computer_name = ws.get('ComputerName', '')
            subnet_id = ws.get('SubnetId', '')

            # CloudWatch Metric
            metrics = cloudwatch_client.get_metric_statistics(
                Namespace='AWS/WorkSpaces',
                MetricName='ConnectionSuccess',
                Dimensions=[{'Name': 'WorkspaceId', 'Value': workspace_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=['Maximum']
            )
            datapoints = metrics.get('Datapoints', [])
            is_inactive = not any(dp['Maximum'] >= 1 for dp in datapoints)

            # Subnet Info
            subnet_info = ec2_client.describe_subnets(SubnetIds=[subnet_id])
            subnet = subnet_info['Subnets'][0]
            subnet_name = ''
            for tag in subnet.get('Tags', []):
                if tag['Key'] == 'Name':
                    subnet_name = tag['Value']

            # LDAP User Info
            conn.search(base_dn, f'(sAMAccountName={user_name})', attributes=['cn', 'sAMAccountName', 'displayName','department','mail','manager','userAccountControl'])
            user_info = conn.entries[0] if conn.entries else None
            user_full_name = user_info.displayName.value if user_info else ''
            user_department = user_info.department.value if user_info else ''
            user_email = user_info.mail.value if user_info else ''
            
            user_enabled = ''
            user_uac_flags = ''
            if user_info:
                uac_value = user_info.userAccountControl.value
                uac_details = parse_user_account_control(uac_value)
                user_enabled = 'Enabled' if uac_details["Enabled"] else 'Disabled'
                user_uac_flags = uac_details["Flags"]
            
            user_manager = ''
            if user_info and user_info.manager.value:
                conn.search(base_dn, f'(distinguishedName={user_info.manager.value})', attributes=['displayName'])
                user_manager = conn.entries[0].displayName.value if conn.entries else ''

            # LDAP Computer Info
            conn.search(base_dn, f'(cn={computer_name})', attributes=['cn','name','whenCreated','operatingSystem','dNSHostName', 'userAccountControl', 'lastLogonTimestamp'])
            computer_info = conn.entries[0] if conn.entries else None
            computer_created = computer_info.whenCreated.value.strftime('%Y-%m-%d %H:%M:%S') if computer_info else ''
            computer_os = computer_info.operatingSystem.value if computer_info else ''
            computer_fqdn = computer_info.dNSHostName.value if computer_info else ''
            computer_enabled = 'Disabled' if (computer_info.userAccountControl.value & 2) else 'Enabled' if computer_info else ''
            ldap_timestamp = computer_info.lastLogonTimestamp.value 
            if isinstance(ldap_timestamp, int):
                computer_last_logon = datetime(1601, 1, 1) + timedelta(microseconds=ldap_timestamp // 10)
            else:
                computer_last_logon = ldap_timestamp  # already a datetime or None


            # Add row
            row = {
                'FullName': user_full_name,
                'UserName': user_name,
                'EmailAddress': user_email,
                'UserEnabled': user_enabled,
                'ComputerName': computer_name,
                'ComputerFullName': computer_fqdn,
                'ComputerEnabled': computer_enabled,
                'ComputerCreated': computer_created,
                'ComputerLastLogon': computer_last_logon.strftime('%Y-%m-%d %H:%M:%S'),
                'WorkSpaceId': workspace_id,
                'WorkSpaceRunningMode': ws.get('WorkspaceProperties', {}).get('RunningMode', ''),
                'WorkSpaceComputeType': ws.get('WorkspaceProperties', {}).get('ComputeTypeName', ''),
                'WorkSpaceIpAddress':  ws.get('IpAddress', ''),
                'WorkSpaceBundleName': workspaces_client.describe_workspace_bundles(BundleIds=[ws.get('BundleId', '')])['Bundles'][0]['Name'],
                'WorkSpaceDirectory' : workspaces_client.describe_workspace_directories(DirectoryIds=[ws.get('DirectoryId', '')])['Directories'][0]['Alias'],
                'WorkSpaceSubnetId': subnet_id
            }
            report_rows.append(row)
        except Exception as e:
            print(f'Error processing workspace {ws.get("WorkspaceId")}: {e}')
            continue

    # Create CSV in memory
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=report_rows[0].keys())
    writer.writeheader()
    writer.writerows(report_rows)

    # Upload to S3
    s3.put_object(Bucket=s3_bucket, Key=s3_key, Body=csv_buffer.getvalue())
    print(f'Report uploaded to s3://{s3_bucket}/{s3_key}')

    # Send notification
    presigned_url = boto3.client('s3', region_name=region).generate_presigned_url(
        'get_object',
        Params={
            'Bucket': s3_bucket,
            'Key': s3_key,
            'ResponseContentDisposition': f'attachment; filename="{s3_key.split("/")[-1]}"'
        },
        ExpiresIn=604800  # 7 days
    )

    message = (
        f"Your WorkSpaces report is ready.\n\n"
        f"Download link (valid for 7 days):\n{presigned_url}"
    )

    response = sns.publish(
            TopicArn=topic_arn,
            Subject=topic_subject,
            Message=message
        )

    return {
    'statusCode': 200,
    'workspace_count': len(report_rows),
    's3_output': f's3://{s3_bucket}/{s3_key}',
    'message': 'Report generated and uploaded successfully.'
}