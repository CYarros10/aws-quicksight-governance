"""
Set up everything permission-related for QuickSight:
    a. Pull user information from S3 location
    b. Iterate through users, determine if they already exist in QuickSight.
    c. if the user's namespace doesn't exist, create it
    d. if user doesn't exist in the namespace, register them
    e. update the users roles. if the role is downgraded, delete the user.
    f. if the user's groups dont exist, create them
    f. if the user isn't a member of the group, assign the user to its groups

Sample User Governance Manifest File:

{
    "username":"aauthor@gmail.com",
    "email":"aauthor@gmail.com"
    "groups":[
        "airtable_devs"
    ]
 }

"""

import os
import traceback
import time
import json
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
import requests
import boto3
from botocore.exceptions import ClientError
import logging

# Logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

FAILURE_RESPONSE = {
    'statusCode': 400,
    'body': "QuickSight User Governance execution has failed",
}

SUCCESS_RESPONSE = {
    'statusCode': 200,
    'body': "QuickSight User Governance execution complete",
}

# Boto3
QS_CLIENT = boto3.client('quicksight')
S3_CLIENT = boto3.client('s3')
SECRETS_CLIENT = boto3.client('secretsmanager')

# Project Variables
QS_PREFIX = os.environ['QS_PREFIX']
QS_FEDERATED_ROLE_NAME = os.environ['QS_FEDERATED_ROLE_NAME']
QS_ADMIN_OKTA_GROUP = os.environ['QS_ADMIN_OKTA_GROUP']
QS_AUTHOR_OKTA_GROUP = os.environ['QS_AUTHOR_OKTA_GROUP']
QS_READER_OKTA_GROUP = os.environ['QS_READER_OKTA_GROUP']

# Slack Secret
SLACK_SECRET_ID = os.environ['SLACK_SECRET_ID']
slack_response = SECRETS_CLIENT.get_secret_value(SecretId=SLACK_SECRET_ID)
slack_secret = json.loads(slack_response["SecretString"])
SLACK_FAILURE_WEBHOOK = slack_secret['slack-failure-webhook']
SLACK_REPORT_WEBHOOK = slack_secret['slack-report-webhook']

@dataclass
class OktaUser:
    """
    Quicksight User data class. Holds information regarding an Okta User mapped
    to a QuickSight User and its permission assignments
    """

    username: str
    email: str
    groups: []
    account: str
    namespace: str
    role: str = field(init=False)

    def __post_init__(self):
        if QS_ADMIN_OKTA_GROUP in self.groups:
            self.role = "ADMIN"
        elif QS_AUTHOR_OKTA_GROUP in self.groups:
            self.role = "AUTHOR"
        elif QS_READER_OKTA_GROUP in self.groups:
            self.role = "READER"
        else:
            self.role = ""


def handler(event, context):
    """
    Handler: Runs QuickSight User Governance
        1) Gets User Information from S3 Object on Put Event
        2) Ensure that the user's namespace exists in QuickSight
        3) Ensure that the user's group exists in QuickSight
        4) Ensure that the user exists in QuickSight
        5) Update the role of the QuickSight user
            a. If the User's role is downgraded, delete and recreate the user.
        6) Add the user to its QuickSight Groups
    """

    LOGGER.info(f"event: {event}")

    account = context.invoked_function_arn.split(":")[4]
    try:
        # Iterate thru event object
        for record in event['Records']:
            # get object details
            bucket = str(record['s3']['bucket']['name'])
            key = str(record['s3']['object']['key'])

            user_info = get_user_info(account, bucket, key)

            for user in user_info:
                ensure_namespace(user)
                ensure_user(user)
                update_role(user)

                if user.groups:
                    ensure_groups(user)
                    update_memberships(user)

            return SUCCESS_RESPONSE
    except Exception as err:
        LOGGER.error(traceback.format_exc())
        notify_slack_failure(context, traceback.format_exc())
        raise Exception(FAILURE_RESPONSE) from err


def get_user_info(account, bucket, key):
    """
    Retrieve user info file and create json object full of okta user information
    """
    user = {}
    key = urllib.parse.unquote(key)
    try:
        data = S3_CLIENT.get_object(Bucket=bucket, Key=key)
        user = json.loads(data['Body'].read().decode('utf-8'))
        user['account'] = account
        user['namespace'] = "default"
    except ClientError as err:
        LOGGER.error(f"Could not retrieve user info file. Error: {str(err)}")
    return [OktaUser(**user)]


def ensure_namespace(user):
    """
    Check to see if a namespace exists in a QuickSight Account.
    If not, create it.
    """

    LOGGER.info(f"Ensuring namespace [{user.namespace}] exists...")

    try:
        QS_CLIENT.describe_namespace(AwsAccountId=user.account, Namespace=user.namespace)
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "ResourceNotFoundException",
            "InvalidParameterValueException",
        ):
            QS_CLIENT.create_namespace(
                AwsAccountId=user.account, Namespace=user.namespace, IdentityStore='QUICKSIGHT'
            )
            time.sleep(60)  # give time for asynchronous namespace create
            LOGGER.info(f"Namespace [{user.namespace}] created.")
        else:
            LOGGER.error(err)


def ensure_user(user):
    """
    Check to see if a user exists in a QuickSight namespace.
    If not, register it.
    """

    LOGGER.info(f"Ensuring user [{user.username}] exists...")

    try:
        QS_CLIENT.describe_user(
            UserName=user.username,
            AwsAccountId=user.account,
            Namespace=user.namespace,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "ResourceNotFoundException",
            "InvalidParameterValueException",
        ):
            if user.role:
                QS_CLIENT.register_user(
                    IdentityType='IAM',
                    Email=user.email,
                    UserRole=user.role,
                    IamArn=f'arn:aws:iam::{user.account}:role/{QS_FEDERATED_ROLE_NAME}',
                    SessionName=user.email,
                    AwsAccountId=user.account,
                    Namespace=user.namespace,
                )
                info_msg = (
                    f"UserGovernance: Added [{user.username}] to Namespace [{user.namespace}]."
                )
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
        else:
            LOGGER.error(err)


def delete_user(user):
    """
    Remove the user from QuickSight
    """
    try:
        QS_CLIENT.delete_user(
            UserName=user.username,
            AwsAccountId=user.account,
            Namespace=user.namespace,
        )
        info_msg = f"UserGovernance: Deleted [{user.username}]."
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    except ClientError as err:
        LOGGER.error(err)


def update_role(user):
    """
    1) Update QuickSight user role.
    2) If the User's role is downgraded, delete the user, then recreate it with
       appropriate role
    """

    try:
        QS_CLIENT.update_user(
            UserName=user.username,
            AwsAccountId=user.account,
            Namespace=user.namespace,
            Role=user.role,
            Email=user.email,
        )
        info_msg = f"UserGovernance: Set [{user.username}] role to: {user.role}"
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "ResourceNotFoundException",
            "InvalidParameterValueException",
        ):
            info_msg = (
                f"UserGovernance: Deleting and recreating user: [{user.username}] "
                "with downgraded role."
            )
            LOGGER.info(info_msg)
            notify_slack_report(info_msg)

            delete_user(user)
            ensure_user(user)
        else:
            LOGGER.error(err)


def ensure_groups(user):
    """
    Check to see if a group exists in a QuickSight namespace.
    If not, create it.
    """

    for grp in user.groups:
        LOGGER.info(f"Ensuring group [{grp}] exists...")
        try:
            QS_CLIENT.describe_group(
                GroupName=grp, AwsAccountId=user.account, Namespace=user.namespace
            )
        except ClientError as err:
            if err.response["Error"]["Code"] in (
                "ResourceNotFoundException",
                "InvalidParameterValueException",
            ):
                QS_CLIENT.create_group(
                    GroupName=grp, AwsAccountId=user.account, Namespace=user.namespace
                )
                info_msg = f"UserGovernance: Added Group [{grp}] to namespace [{user.namespace}]"
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
            else:
                LOGGER.error(err)


def get_memberships(user):
    """
    Get list of QuickSight User's current groups
    """

    LOGGER.info(f"Getting list of user [{user.username}] current groups...")
    memberships = []
    list_users_response = QS_CLIENT.list_user_groups(
        UserName=user.username,
        AwsAccountId=user.account,
        Namespace=user.namespace,
    )

    for grp in list_users_response['GroupList']:
        memberships.append(grp['GroupName'])

    return memberships


def update_memberships(user):
    """
    Assign a user to its new groups and remove the user from groups it no
    longer belongs to.
    """

    LOGGER.info(f"Updating group memberships for user [{user.username}]...")
    current_memberships = get_memberships(user)
    # assign user to new groups
    for grp in user.groups:
        if grp not in current_memberships:
            QS_CLIENT.create_group_membership(
                MemberName=user.username,
                GroupName=grp,
                AwsAccountId=user.account,
                Namespace=user.namespace,
            )
            info_msg = f"UserGovernance: Assigned [{user.username}] to Group [{grp}]."
            LOGGER.info(info_msg)
            notify_slack_report(info_msg)
    # remove user from old groups
    for grp in current_memberships:
        if grp not in user.groups:
            QS_CLIENT.delete_group_membership(
                MemberName=user.username,
                GroupName=grp,
                AwsAccountId=user.account,
                Namespace=user.namespace,
            )
            info_msg = f"UserGovernance: Removed [{user.username}] from Group [{grp}]."
            LOGGER.info(info_msg)
            notify_slack_report(info_msg)


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
