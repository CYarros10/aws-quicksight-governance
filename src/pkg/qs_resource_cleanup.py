"""
Due to the nature of the QuickSight Governance solution, there must be a process
in place to delete QuickSight resources that map to Okta resources that are no
longer in use. (i.e. if an Okta User or Okta Group is removed from the Okta
Application, we need to remove them from QuickSight as well.)

This function periodically cleans up several QuickSight resources:
    - QuickSight Users
    - QuickSight Groups
    - QuickSight IAM Policy Assignments
    - IAM Policies utilized by QuickSight IAM Policy Assignments

For this to happen we need to:
   a. Load what SHOULD exist in QuickSight from the S3 manifest files for users,
      groups, namespaces, policies, etc.
   b. Get what currently exists in QuickSight
   c. Compare what SHOULD exist in QuickSight (newest) with what CURRENTLY exists,
      (outdated) and remove resources that don't match.

extra: If QuickSight Users are errored out and appear as duplicates in console,
       or N/A in CLI, remove those duplicated/errored users.

"""

import os
import json
import traceback
from datetime import datetime
import boto3
import requests
from botocore.exceptions import ClientError
import logging

# Logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

FAILURE_RESPONSE = {
    'statusCode': 400,
    'body': "QuickSight Cleanup execution has failed",
}

SUCCESS_RESPONSE = {
    'statusCode': 200,
    'body': "QuickSight Cleanup execution complete",
}

# Boto3
QS_CLIENT = boto3.client('quicksight')
IAM_CLIENT = boto3.client('iam')
S3_RESOURCE = boto3.resource('s3')
SECRETS_CLIENT = boto3.client('secretsmanager')

# Project Variables
QS_PREFIX = os.environ['QS_PREFIX']
QS_SUPERUSER = os.environ['QS_SUPERUSER']
BUCKET_NAME = os.environ['QS_GOVERNANCE_BUCKET']
S3_PREFIX_USERS = os.environ['S3_PREFIX_USERS']
S3_PREFIX_ASSETS = os.environ['S3_PREFIX_ASSETS']
S3_PREFIX_POLICIES = os.environ['S3_PREFIX_POLICIES']

# Global Variables
NEW_QS_USERS = set()
NEW_QS_GROUPS = set()
NEW_QS_NAMESPACES = set()
NEW_IAM_POLICY_ARNS = set()
NEW_QS_IAM_POLICY_ASSIGNMENTS = set()
NEW_QS_NAMESPACES.add('default')

# Slack Secret
SLACK_SECRET_ID = os.environ['SLACK_SECRET_ID']
slack_response = SECRETS_CLIENT.get_secret_value(SecretId=SLACK_SECRET_ID)
slack_secret = json.loads(slack_response["SecretString"])
SLACK_FAILURE_WEBHOOK = slack_secret['slack-failure-webhook']
SLACK_REPORT_WEBHOOK = slack_secret['slack-report-webhook']


def handler(event, context):
    """
    Handler: Runs QuickSight Cleanup
        1) Load the sets of latest QuickSight resources
        2) Remove Groups that should no longer exist in QuickSight
        3) Remove Users that should no longer exist in QuickSight
        4) Remove IAM Policy Assignments that should no longer exist in
           QuickSight
        5) Remove IAM Policies that were utilized by deleted IAM Policy
           Assignments
    """
    LOGGER.info(f"event: {event}")

    try:
        account_id = context.invoked_function_arn.split(":")[4]

        load_new_resources(account_id)

        for namespace in NEW_QS_NAMESPACES:
            remove_old_groups(account_id, namespace)
            remove_old_users(account_id, namespace)
            remove_old_policy_assignments(account_id, namespace)
            remove_old_iam_policies(account_id)

        return SUCCESS_RESPONSE

    except Exception as err:
        LOGGER.error(traceback.format_exc())
        notify_slack_failure(context, traceback.format_exc())
        raise Exception(FAILURE_RESPONSE) from err


def load_new_resources(account_id):
    """
    Update sets with the newest QuickSight resources that are recorded in S3
    manifest files
    """

    gov_bucket = S3_RESOURCE.Bucket(BUCKET_NAME)
    NEW_QS_USERS.add(QS_SUPERUSER)

    for obj in gov_bucket.objects.filter(Prefix=S3_PREFIX_USERS):
        key = obj.key
        user_obj = S3_RESOURCE.Object(gov_bucket.name, key)
        user_json = json.loads(user_obj.get()['Body'].read().decode('utf-8'))
        NEW_QS_USERS.add(user_json['username'])
        for grp in user_json['groups']:
            NEW_QS_GROUPS.add(grp)

    for obj in gov_bucket.objects.filter(Prefix=S3_PREFIX_POLICIES):
        key = obj.key
        policy_obj = S3_RESOURCE.Object(gov_bucket.name, key)
        policy_json = json.loads(policy_obj.get()['Body'].read().decode('utf-8'))
        for pol in policy_json['policies']:
            group = pol['group']
            policy_name = f"{group}_policy"
            NEW_QS_IAM_POLICY_ASSIGNMENTS.add(policy_name)

            arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
            NEW_IAM_POLICY_ARNS.add(arn)


def get_outdated_namespaces(account_id):
    """
    Get outdated QuickSight namespace list
    """

    outdated_namespaces = []
    response = QS_CLIENT.list_namespaces(AwsAccountId=account_id)
    for namespace in response['Namespaces']:
        outdated_namespaces.append(namespace['Name'])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_namespaces(
            AwsAccountId=account_id, NextToken=response.get("NextToken")
        )
        for namespace in response['Namespaces']:
            outdated_namespaces.append(namespace['Name'])

    return outdated_namespaces


def get_outdated_groups(account_id, namespace):
    """
    Get outdated QuickSight group list
    """

    outdated_groups = []
    response = QS_CLIENT.list_groups(AwsAccountId=account_id, Namespace=namespace)
    for grp in response['GroupList']:
        outdated_groups.append(grp['GroupName'])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_groups(
            AwsAccountId=account_id, Namespace=namespace, NextToken=response.get("NextToken")
        )
        for grp in response['GroupList']:
            outdated_groups.append(grp['GroupName'])

    return outdated_groups


def get_outdated_users(account_id, namespace):
    """
    - Get outdated QuickSight user list
    - remove errored users
    """

    outdated_users = []
    response = QS_CLIENT.list_users(AwsAccountId=account_id, Namespace=namespace)
    for user in response['UserList']:
        if user['UserName'] == 'N/A':
            remove_errored_user(account_id, namespace, user)
        else:
            outdated_users.append(user['UserName'])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_users(
            AwsAccountId=account_id, Namespace=namespace, NextToken=response.get("NextToken")
        )
        for user in response['UserList']:
            if user['UserName'] == 'N/A':
                remove_errored_user(account_id, namespace, user)
            else:
                outdated_users.append(user['UserName'])

    return outdated_users


def get_outdated_policy_assignments(account_id, namespace):
    """
    Get outdated IAM Policy Assignments list
    """

    outdated_assignments = []
    response = QS_CLIENT.list_iam_policy_assignments(AwsAccountId=account_id, Namespace=namespace)
    for asg in response['IAMPolicyAssignments']:
        outdated_assignments.append(asg['AssignmentName'])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_iam_policy_assignments(
            AwsAccountId=account_id, Namespace=namespace, NextToken=response.get("NextToken")
        )
        for asg in response['IAMPolicyAssignments']:
            outdated_assignments.append(asg['AssignmentName'])

    return outdated_assignments


def get_outdated_policies():
    """
    Get list of existing IAM Policies utilized by QuickSight Governance Solution
    """

    outdated_policy_arns = []
    paginator = IAM_CLIENT.get_paginator('list_policies')
    page_iterator = paginator.paginate(Scope='Local')
    for page in page_iterator:
        for policy in page['Policies']:
            if QS_PREFIX in policy['PolicyName']:
                outdated_policy_arns.append(policy['Arn'])

    return outdated_policy_arns


def remove_old_users(account_id, namespace):
    """
    Remove users from QuickSight that no longer exist in Okta
    """

    LOGGER.info("Removing users that should no longer exist in QuickSight...")
    outdated_users = get_outdated_users(account_id, namespace)
    for user in outdated_users:
        if user not in NEW_QS_USERS:
            try:
                QS_CLIENT.delete_user(AwsAccountId=account_id, Namespace=namespace, UserName=user)
                info_msg = f"ResourceCleanup: Deleted user [{user}]."
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
            except ClientError as err:
                LOGGER.error(err)


def remove_errored_user(account_id, namespace, user):
    """
    If a Federated Role is deleted before the QuickSight user is deleted,
    they will be in an error-state where their username is 'N/A'. The only way
    to delete the user is via their principal ID.
    """

    LOGGER.info("Removing errored user that should no longer exist in QuickSight...")
    try:
        principalid = user['PrincipalId']
        QS_CLIENT.delete_user_by_principal_id(
            PrincipalId=principalid, AwsAccountId=account_id, Namespace=namespace
        )
        info_msg = f"ResourceCleanup: Deleted errored user via PrincipalId: {principalid}"
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    except ClientError as err:
        LOGGER.error(err)


def remove_old_groups(account_id, namespace):
    """
    Remove groups from QuickSight that no longer exist in Okta
    """

    LOGGER.info("Removing groups that should no longer exist in QuickSight...")
    outdated_groups = get_outdated_groups(account_id, namespace)
    for group in outdated_groups:
        if group not in NEW_QS_GROUPS:
            try:
                QS_CLIENT.delete_group(
                    AwsAccountId=account_id, Namespace=namespace, GroupName=group
                )
                info_msg = f"ResourceCleanup: Deleted group [{group}]."
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
            except ClientError as err:
                LOGGER.error(err)


def remove_old_policy_assignments(account_id, namespace):
    """
    Remove iam policy assignments from quicksight that not longer exist in S3
    Manifest files
    """

    LOGGER.info("Removing IAM Policy Assignments that should no longer exist in QuickSight...")
    outdated_policy_assignments = get_outdated_policy_assignments(account_id, namespace)
    base_policy_name = f"{QS_PREFIX}_base_policy"
    for assignment in outdated_policy_assignments:
        if assignment not in NEW_QS_IAM_POLICY_ASSIGNMENTS and assignment != base_policy_name:
            try:
                QS_CLIENT.delete_iam_policy_assignment(
                    AwsAccountId=account_id, AssignmentName=assignment, Namespace=namespace
                )
                info_msg = f"ResourceCleanup: Deleted IAM Policy Assignment [{assignment}]."
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
            except ClientError as err:
                LOGGER.error(err)


def remove_old_iam_policies(account_id):
    """
    Remove IAM Policies that are no longer in use by QuickSight IAM Policy
    Assignments
    """

    LOGGER.info("Removing IAM Policies that are no longer used in QuickSight...")
    outdated_policies = get_outdated_policies()
    base_policy = f"arn:aws:iam::{account_id}:policy/{QS_PREFIX}_base_policy"
    for arn in outdated_policies:
        if (
            arn not in NEW_IAM_POLICY_ARNS and arn != base_policy
        ):  # don't delete the base policy for any reason
            try:
                IAM_CLIENT.delete_policy(PolicyArn=arn)
                info_msg = f"ResourceCleanup: Deleted IAM Policy [{arn}]."
                LOGGER.info(info_msg)
                notify_slack_report(info_msg)
            except ClientError as err:
                LOGGER.error(err)


def notify_slack_failure(context, details) -> int:
    """Send message to Slack channel"""

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
