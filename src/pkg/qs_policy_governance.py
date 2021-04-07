"""
Generate IAM Policies for Quicksight IAM Policy Assignment:
    a. Get Manifest file from S3 containing Group to Database Permissions
    b. Generate IAM Policy for access to that set of databases in glue.
    c. iam policy will have catalog access to the databases provided in the policy_info.
    d. assign base policy to qs authors and admins

Sample Policy Governance Manifest File:

{
    "policies":[
       {
            "group": "dlp_qs_dev_group_pandora",
            "databases": [
                {
                    "name": "pandora_dev",
                    "tables": [
                        "payment_execution_service",
                        "scheduled_payments"
                    ]
                }
            ]
       }
    ]
}
"""

import os
import traceback
import json
import time
from datetime import datetime
from typing import List
from dataclasses import dataclass, field
import boto3
import requests
from botocore.exceptions import ClientError
import logging

# Logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

FAILURE_RESPONSE = {
    'statusCode': 400,
    'body': "QuickSight Policy Governance execution has failed",
}

SUCCESS_RESPONSE = {
    'statusCode': 200,
    'body': "QuickSight Policy Governance execution complete",
}

# Boto3
QS_CLIENT = boto3.client('quicksight')
S3_CLIENT = boto3.client('s3')
IAM_CLIENT = boto3.client('iam')
SECRETS_CLIENT = boto3.client('secretsmanager')

# Project Variables
REGION = os.environ['AWS_REGION']
QS_ADMIN_OKTA_GROUP = os.environ['QS_ADMIN_OKTA_GROUP']
QS_AUTHOR_OKTA_GROUP = os.environ['QS_AUTHOR_OKTA_GROUP']
QS_AUTHOR_BASE_POLICY = os.environ['QS_AUTHOR_BASE_POLICY']
TEST_BUCKET = os.environ["QS_GOVERNANCE_BUCKET"]
TEST_PREFIX = os.environ["S3_PREFIX_POLICIES"]
QS_SUPERUSER = os.environ['QS_SUPERUSER']
DEPLOYMENT_STAGE = os.environ['DEPLOYMENT_STAGE']

# Slack Secret
SLACK_SECRET_ID = os.environ['SLACK_SECRET_ID']
slack_response = SECRETS_CLIENT.get_secret_value(SecretId=SLACK_SECRET_ID)
slack_secret = json.loads(slack_response["SecretString"])
SLACK_FAILURE_WEBHOOK = slack_secret['slack-failure-webhook']
SLACK_REPORT_WEBHOOK = slack_secret['slack-report-webhook']


@dataclass
class QuickSightPolicy:
    """
    Quicksight Policy data class. Holds information regarding an Okta User
    mapped to a QuickSight User and its permission assignments.
    """

    group: str
    databases: List[dict]
    account_id: str
    namespace: str
    name: str = field(init=False)
    arn: str = field(init=False)
    document: str = field(init=False)

    def __post_init__(self):
        self.name = f"{self.group}_policy"
        self.arn = f"arn:aws:iam::{self.account_id}:policy/{self.name}"

        resources = []
        resources.append(f"arn:aws:glue:{REGION}:{self.account_id}:catalog")

        for database in self.databases:
            db_name = f"{database['name']}_{DEPLOYMENT_STAGE}"
            resources.append(f"arn:aws:glue:{REGION}:{self.account_id}:database/{db_name}")
            for table in database['tables']:
                resources.append(f"arn:aws:glue:{REGION}:{self.account_id}:table/{db_name}/{table}")

        self.document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "glue:GetDatabase",
                        "glue:GetDatabases",
                        "glue:GetTable",
                        "glue:GetPartitions",
                        "glue:GetPartition",
                        "glue:GetTables",
                    ],
                    "Resource": resources,
                }
            ],
        }


def handler(event, context):
    """
    Handler: Runs QuickSight Policy Governance
        1) Upon Policy Manifest File landing in S3, begin Policy Governance
        2) Ensure that the IAM Policy exists for data lake access for a QS group
        3) Assign that IAM Policy to the group
    """

    LOGGER.info(f"event: {event}")

    try:
        account_id = context.invoked_function_arn.split(":")[4]

        # Quicker testing
        if "bucket" not in event:
            LOGGER.info("Running Test...")
            test_key = f"{TEST_PREFIX}qs-policy-governance-test.json"
            run_governance(account_id, TEST_BUCKET, test_key)
        else:
            for record in event['Records']:
                bucket = str(record['s3']['bucket']['name'])
                key = str(record['s3']['object']['key'])
                run_governance(account_id, bucket, key)

        return SUCCESS_RESPONSE

    except Exception as err:
        LOGGER.error(traceback.format_exc())
        notify_slack_failure(context, traceback.format_exc())
        raise Exception(FAILURE_RESPONSE) from err


def get_policy_info(account_id, bucket, key):
    """
    Retrieve policy manifest file and create json object
    """
    policies = {}
    try:
        data = S3_CLIENT.get_object(Bucket=bucket, Key=key)
        json_data = json.loads(data['Body'].read().decode('utf-8'))
        policies = json_data["policies"]
        for policy in policies:
            policy['account_id'] = account_id
    except ClientError as err:
        LOGGER.error(f"Could not retrieve policy manifest file. Error: {str(err)}")
        raise ClientError from err
    return [QuickSightPolicy(**policy) for policy in policies]


def run_governance(account_id, bucket, key):
    """
    Policy Governance
        1) Delete and Recreate an IAM Policy (to ensure its up to date)
        2) Create/Update the IAM Policy Assignment to the specified QS Group
        3) Create/Update the Base IAM Policy to QS Authors Group
    """

    policy_info = get_policy_info(account_id, bucket, key)

    for policy in policy_info:
        recreate_iam_policy(policy)
        assign_policy_to_group(policy)

    assign_base_policy(account_id)


def recreate_iam_policy(policy):
    """
    Delete and Recreate an IAM Policy
    """
    try:
        IAM_CLIENT.delete_policy(PolicyArn=policy.arn)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            LOGGER.info(f"Policy for group [{policy.group}] doesn't exist")
        else:
            LOGGER.error(f"Failed to delete IAM Policy for group [{policy.group}]: {err}")

    # give time for AWS to propagate IAM changes
    time.sleep(3)

    try:
        IAM_CLIENT.create_policy(
            PolicyName=policy.name,
            PolicyDocument=json.dumps(policy.document),
            Description='QS IAM Policy Assignment for fine-grained access to AWS Data Catalog',
        )
        info_msg = (
            f"PolicyGovernance: Created IAM policy [{policy.name}] for group [{policy.group}]"
        )
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    except ClientError as err:
        LOGGER.error(f"Failed to create the IAM Policy for group [{policy.group}]: {err}")


def assign_policy_to_group(policy):
    """
    Assign an IAM Policy to a QuickSight Group.
    """

    try:
        QS_CLIENT.create_iam_policy_assignment(
            AwsAccountId=policy.account_id,
            AssignmentName=policy.name,
            AssignmentStatus='ENABLED',
            PolicyArn=policy.arn,
            Identities={"Group": [policy.group], "User": [QS_SUPERUSER]},
            Namespace=policy.namespace,
        )
        info_msg = f"PolicyGovernance: Assigned policy [{policy.name}] to group [{policy.group}]"
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    except ClientError as err:
        if err.response['Error']['Code'] == 'ResourceExistsException':
            QS_CLIENT.update_iam_policy_assignment(
                AwsAccountId=policy.account_id,
                AssignmentName=policy.name,
                AssignmentStatus='ENABLED',
                PolicyArn=policy.arn,
                Identities={"Group": [policy.group], "User": [QS_SUPERUSER]},
                Namespace=policy.namespace,
            )
            info_msg = (
                f"PolicyGovernance: Updated policy [{policy.name}] for group [{policy.group}]"
            )
            LOGGER.info(info_msg)
            notify_slack_report(info_msg)
        else:
            LOGGER.error(f"Failed to assign IAM Policy for group [{policy.group}]: {err}")


def assign_base_policy(account_id):
    """
    Assign the QS Author Base IAM Policy containing permissions that all
    QuickSight authors/admins need for access to AWS Data Catalog.
    """

    try:
        QS_CLIENT.create_iam_policy_assignment(
            AwsAccountId=account_id,
            AssignmentName=QS_AUTHOR_BASE_POLICY,
            AssignmentStatus='ENABLED',
            PolicyArn=f"arn:aws:iam::{account_id}:policy/{QS_AUTHOR_BASE_POLICY}",
            Identities={
                "Group": [QS_AUTHOR_OKTA_GROUP, QS_ADMIN_OKTA_GROUP],
                "User": [QS_SUPERUSER],
            },
            Namespace='default',
        )
        LOGGER.info("Created Base Policy for QuickSight Authors/Admins.")
    except ClientError as err:
        if err.response['Error']['Code'] == 'ResourceExistsException':
            QS_CLIENT.update_iam_policy_assignment(
                AwsAccountId=account_id,
                AssignmentName=QS_AUTHOR_BASE_POLICY,
                AssignmentStatus='ENABLED',
                PolicyArn=f"arn:aws:iam::{account_id}:policy/{QS_AUTHOR_BASE_POLICY}",
                Identities={
                    "Group": [QS_AUTHOR_OKTA_GROUP, QS_ADMIN_OKTA_GROUP],
                    "User": [QS_SUPERUSER],
                },
                Namespace='default',
            )
            LOGGER.info("Updated Base Policy for QuickSight Authors/Admins.")
        else:
            LOGGER.error(err)


def notify_slack_failure(context, details) -> int:
    """
    Send message to Slack channel
    """

    message = {}
    message['service'] = "aws_lambda"
    message['service_name'] = context.function_name
    message['time'] = str(datetime.utcnow())
    message['request_id'] = context.aws_request_id
    message['log_group'] = context.log_group_name
    message['log_stream'] = context.log_stream_name
    message['details'] = json.dumps(details, indent=4, sort_keys=True)

    req = requests.post(
        url=SLACK_FAILURE_WEBHOOK,
        data=json.dumps(message),
        headers={'Content-Type': 'application/json'},
    )

    return req.status_code


def notify_slack_report(message):
    """
    Send report to slack channel
    """
    content = {}
    content['message'] = message

    req = requests.post(
        url=SLACK_REPORT_WEBHOOK,
        data=json.dumps(content),
        headers={'Content-Type': 'application/json'},
    )

    return req.status_code
