"""
Sync Okta Application User Information with S3 Location.
    a. Get Okta Users Information and convert to json
    b. Upload new user json files to S3
    c. Remove old user json files from S3 (i.e. user is no longer associated w/
       the Okta Application)

"""

import os
import traceback
import json
from datetime import datetime
import urllib3
import boto3
import requests
from botocore.exceptions import ClientError
import logging

# Logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


FAILURE_RESPONSE = {
    'statusCode': 400,
    'body': "Okta User Information Retrieval execution has failed",
}

SUCCESS_RESPONSE = {
    'statusCode': 200,
    'body': "Okta User Information Retrieval execution complete",
}

# Boto3
S3_RESOURCE = boto3.resource('s3')
SECRETS_CLIENT = boto3.client('secretsmanager')

# Project Variables
QS_GOVERNANCE_BUCKET = os.environ['QS_GOVERNANCE_BUCKET']
QS_FEDERATED_ROLE_NAME = os.environ['QS_FEDERATED_ROLE_NAME']
QS_PREFIX = os.environ['QS_PREFIX']
S3_PREFIX_USERS = os.environ['S3_PREFIX_USERS']

# Urllib3
HTTP = urllib3.PoolManager()

# Okta Specific Secrets
OKTA_SECRET_ID = os.environ['OKTA_SECRET_ID']
response = SECRETS_CLIENT.get_secret_value(SecretId=OKTA_SECRET_ID)
okta_secret = json.loads(response["SecretString"])
OKTA_APP_ID = okta_secret['okta-app-id-secret']
OKTA_APP_TOKEN = okta_secret['okta-app-token-secret']
OKTA_URL = okta_secret["okta-api-url"]
OKTA_AUTH = f"SSWS {OKTA_APP_TOKEN}"

# Slack Secret
SLACK_SECRET_ID = os.environ['SLACK_SECRET_ID']
slack_response = SECRETS_CLIENT.get_secret_value(SecretId=SLACK_SECRET_ID)
slack_secret = json.loads(slack_response["SecretString"])
SLACK_FAILURE_WEBHOOK = slack_secret['slack-failure-webhook']
SLACK_REPORT_WEBHOOK = slack_secret['slack-report-webhook']


def handler(event, context):
    """
    Handler: Runs GetOktaInformation
        1) Get User Info from Okta via API
        2) Upload okta user info to S3
        3) Remove old user info from S3
    """

    LOGGER.info(f"event: {event}")

    try:
        LOGGER.info("Getting okta information...")
        okta_response = get_users()
        okta_users = []

        LOGGER.info("Uploading new users...")
        for user in okta_response:
            user_info = generate_user_qs_info(user)
            okta_users.append(user_info['username'])
            s3_upload(user_info)

        LOGGER.info("Removing old users...")
        outdated_users = get_outdated_users()
        for user_info in outdated_users:
            if user_info not in okta_users:
                s3_delete(user_info)

        return SUCCESS_RESPONSE

    except Exception as err:
        LOGGER.error(traceback.format_exc())
        notify_slack_failure(context, traceback.format_exc())
        raise Exception(FAILURE_RESPONSE) from err


def get_users():
    """
    Use urllib3 to make a REST call to get list of Okta
    Users for a given Okta Application
    """
    request_url = f"{OKTA_URL}/apps/{OKTA_APP_ID}/users"
    print(request_url)
    okta_users_request = HTTP.request(
        'GET',
        request_url,
        headers={'Content-Type': 'application/json', 'Authorization': OKTA_AUTH},
        retries=False,
    )
    users = json.loads(okta_users_request.data.decode('utf-8'))
    return users


def get_outdated_users():
    """
    Get a list of usernames that have been previously uploaded and exist in
    s3/quicksight
    """
    qs_bucket = S3_RESOURCE.Bucket(QS_GOVERNANCE_BUCKET)
    outdated_users = []
    for obj in qs_bucket.objects.filter(Prefix=S3_PREFIX_USERS):
        rm_prefix_user = obj.key.replace(S3_PREFIX_USERS, '')
        user = rm_prefix_user.replace('.json', '')
        outdated_users.append(user)
    return outdated_users


def get_users_okta_groups(okta_user_id):
    """
    Use urllib3 to make a REST call to get list of Okta
    Users Groups Memberships from a specific okta user id
    """
    request_url = f"{OKTA_URL}/users/{okta_user_id}/groups"
    group_memberships_request = HTTP.request(
        'GET',
        request_url,
        headers={'Content-Type': 'application/json', 'Authorization': OKTA_AUTH},
        retries=False,
    )
    group_memberships = json.loads(group_memberships_request.data.decode('utf-8'))
    return group_memberships


def generate_user_qs_info(user):
    """
    Build QuickSight Users info obj from the HTTP Request json. Only add QS
    Groups.(QS PREFIX)
    """
    groups = []
    group_memberships = get_users_okta_groups(user['id'])
    for grp in group_memberships:
        if QS_PREFIX in grp['profile']['name']:
            groups.append(grp['profile']['name'])

    okta_username = user['credentials']['userName']
    qs_username = f"{QS_FEDERATED_ROLE_NAME}/{okta_username}"
    user_manifest = {
        "username": qs_username,
        "email": okta_username,
        "groups": groups,
    }
    return user_manifest


def s3_upload(user_info):
    """
    Upload new user info to an S3 object
    """

    incoming = json.dumps(user_info)
    existing = ""
    username = str(user_info['username'])
    try:
        key = f"{S3_PREFIX_USERS}{username}.json"
        existing = (
            S3_RESOURCE.Object(QS_GOVERNANCE_BUCKET, key).get()['Body'].read().decode('utf-8')
        )
    except ClientError as err:
        LOGGER.info(err)

    if incoming != existing:
        key = f"{S3_PREFIX_USERS}{username}.json"
        s3object = S3_RESOURCE.Object(QS_GOVERNANCE_BUCKET, key)
        s3object.put(Body=(bytes(json.dumps(user_info).encode('UTF-8'))))
        info_msg = (
            f"GetOktaInformation: Uploaded Okta user [{username}] "
            f"to s3://{QS_GOVERNANCE_BUCKET}/{key}"
        )
        LOGGER.info(info_msg)
        notify_slack_report(info_msg)
    else:
        LOGGER.info(f"GetOktaInformation: Okta user [{username}] unchanged. no upload needed.")


def s3_delete(username):
    """
    Delete a user's S3 file
    """

    key = f"{S3_PREFIX_USERS}{username}.json"
    s3object = S3_RESOURCE.Object(QS_GOVERNANCE_BUCKET, key)
    s3object.delete()
    info_msg = (
        f"GetOktaInformation: Removed Okta user [{username}] from s3://{QS_GOVERNANCE_BUCKET}/{key}"
    )
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
