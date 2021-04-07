"""Constants file for resource naming and env values"""
import os

###################################
# Account Setup
###################################

# AWS Account Region
REGION = "us-east-1"

STAGE_PROD = 'prod'
STAGE_DEV = 'dev'

DEPLOYMENT_STAGE = os.environ["DEPLOYMENT_STAGE"]

# Data Engineering
ACCOUNTS = {
    STAGE_PROD: "<INSERT>",
    STAGE_DEV: "<INSERT>"
}

ACCOUNT = ACCOUNTS[DEPLOYMENT_STAGE]
CDK_ENV = {"account": ACCOUNTS[DEPLOYMENT_STAGE], "region": REGION}

###################################
# Project Setup
###################################

# Name of the Solution
PROJECT = "QSGovernance"

# Secrets Manager Secret created prior to solution deployment (holds Okta info for API calls)
OKTA_SECRET_ID = "okta-quicksight-secret"

# IAM Identity Provider created prior to solution deployment (allows connection of AWS and Okta)
OKTA_IDP_NAME = "okta-idp"

# Prefix for most/all AWS and QuickSight resources related to this solution
QS_PREFIX = "qs_gov"

# The name of the role assumed by Okta users when logging into QuickSight. (changing this may create duplicate users)
QS_FEDERATED_ROLE_NAME = f"{QS_PREFIX}_FederatedRole"

# Okta Groups that map to QuickSight User Roles (must be created in Okta first)
QS_ADMIN_OKTA_GROUP = f"{QS_PREFIX}_role_admin"
QS_AUTHOR_OKTA_GROUP = f"{QS_PREFIX}_role_author"
QS_READER_OKTA_GROUP = f"{QS_PREFIX}_role_reader"

# name of the Base IAM Policy given to QuickSight Authors
QS_AUTHOR_BASE_POLICY = f"{QS_PREFIX}_base_policy"

# The QuickSight Username of the person that initiated QuickSight in the AWS Account
QS_SUPERUSER = "<INSERT>"

# S3 Folder Locations for manifests that describe QuickSight resources
S3_PREFIX_USERS = f"{QS_PREFIX}/users/"
S3_PREFIX_ASSETS = f"{QS_PREFIX}/assets/"
S3_PREFIX_POLICIES = f"{QS_PREFIX}/policies/"

# Athena Output Location

ATHENA_QUERY_BUCKETS = {
    STAGE_PROD: "<INSERT>",
    STAGE_DEV: "<INSERT>"
}

ATHENA_OUTPUT_LOC = ATHENA_QUERY_BUCKETS[DEPLOYMENT_STAGE]

# Slack Webhook Secret
SLACK_SECRET_ID = "qs-gov-slack-webhook"

# Verified Email for Asset Governance Reporting
VERIFIED_EMAIL = "<INSERT>"

###################################
# CDK Misc.
###################################

PATH_CDK = os.path.dirname(os.path.abspath(__file__))
PATH_ROOT = os.path.dirname(PATH_CDK)
PATH_SRC = os.path.join(PATH_ROOT, 'src')