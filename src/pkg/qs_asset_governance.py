"""
Ensure that users only view QuickSight Resources that they have data access to.
    a. Get all datasets, dashboards, analyses, users, groups
    b. Get user table permissions based on group membership
    c. Get all athena tables used in a dashboard, analyses, dataset
    d. Handles inadequate dashboard, analysis, dataset permissions based on table permissions needed

Why? - All QuickSight Resource permissions are derived strictly from the data that a user has
access to. (simplification)

"""
import os
import traceback
import json
import time
from datetime import datetime
from typing import List, Dict, Set, Iterator
from dataclasses import dataclass, field
import requests
import boto3
from botocore.exceptions import ClientError
import logging

# Logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

FAILURE_RESPONSE = {
    "statusCode": 400,
    "body": "QuickSight asset governance has failed",
}

SUCCESS_RESPONSE = {
    "statusCode": 200,
    "body": "QuickSight asset governance execution complete",
}

# Permissions that identify Admin
QS_DASHBOARD_ADMIN_ACTION = "quicksight:UpdateDashboardPermissions"
QS_ANALYSIS_ADMIN_ACTION = "quicksight:UpdateAnalysisPermissions"
QS_DATA_SET_ADMIN_ACTION = "quicksight:UpdateDataSetPermissions"

# Boto3
QS_CLIENT = boto3.client("quicksight")
S3_CLIENT = boto3.client("s3")
SECRETS_CLIENT = boto3.client("secretsmanager")
SES_CLIENT = boto3.client('ses')

# Environment Variables
STAGE = os.environ.get("STAGE", "dev")
BUCKET = os.environ.get("QS_GOVERNANCE_BUCKET", "")
S3_PREFIX_USERS = os.environ.get("S3_PREFIX_USERS", "dlp_qs/users/")
S3_PREFIX_POLICIES = os.environ.get("S3_PREFIX_POLICIES", "dlp_qs/policies/")
VERIFIED_EMAIL = os.environ.get("VERIFIED_EMAIL", "")

# Slack Secret
SLACK_SECRET_ID = os.environ['SLACK_SECRET_ID']
slack_response = SECRETS_CLIENT.get_secret_value(SecretId=SLACK_SECRET_ID)
slack_secret = json.loads(slack_response["SecretString"])
SLACK_FAILURE_WEBHOOK = slack_secret['slack-failure-webhook']
SLACK_REPORT_WEBHOOK = slack_secret['slack-report-webhook']


@dataclass
class GroupDatabaseConfig:
    """
    DatabaseConfig within QuicksightGroupConfig
    """

    name: str
    tables: List[str]
    resolved_tables: List[str] = field(init=False)

    def __post_init__(self):
        """set resolved tables"""
        self.resolved_tables = [f"{self.name}_{STAGE}.{table}" for table in self.tables]


@dataclass
class QuicksightGroupConfig:
    """
    Quicksight Policy Config container
    """

    group: str
    namespace: str
    databases: List[GroupDatabaseConfig]


@dataclass
class QuicksightUser:
    """
    Quicksight User Config container
    """

    username: str
    email: str
    groups: List[str]
    table_permissions: Set[str] = field(init=False, default_factory=lambda: set())

    def set_table_grants(self, all_groups: Dict[str, QuicksightGroupConfig]) -> None:
        """Set table grants for user"""
        for user_group in self.groups:
            if user_group in all_groups:
                for database_config in all_groups[user_group].databases:
                    for resolved_table in database_config.resolved_tables:
                        self.table_permissions.add(resolved_table)


class QuickSightAsset:
    """
    A QuickSight Asset (Dashboard, Analysis, Data Set) and its permissions.
    """

    def __init__(self, account_id: str, asset_id: str, asset_type: str):
        self.asset_type = asset_type
        self.asset_id = asset_id
        self.account_id = account_id
        self._detail = None
        self._permissions = None

    @property
    def detail(self) -> Dict:
        """
        Get Asset Details
        """
        if self._detail is None:
            if self.asset_type == "dashboard":
                data = QS_CLIENT.describe_dashboard(
                    AwsAccountId=self.account_id, DashboardId=self.asset_id
                )
                self._detail = data["Dashboard"]
            elif self.asset_type == "analysis":
                data = QS_CLIENT.describe_analysis(
                    AwsAccountId=self.account_id, AnalysisId=self.asset_id
                )
                self._detail = data["Analysis"]
            elif self.asset_type == "dataset":
                data = QS_CLIENT.describe_data_set(
                    AwsAccountId=self.account_id, DataSetId=self.asset_id
                )
                time.sleep(2)
                self._detail = data["DataSet"]
            else:
                LOGGER.error("Couldn't determine asset type.")
        return self._detail

    @property
    def permissions(self) -> List[Dict]:
        """
        Gets Asset permissions
        """
        if self._permissions is None:
            if self.asset_type == "dashboard":
                data = QS_CLIENT.describe_dashboard_permissions(
                    AwsAccountId=self.account_id, DashboardId=self.asset_id
                )
                self._permissions = data["Permissions"]
            elif self.asset_type == "analysis":
                data = QS_CLIENT.describe_analysis_permissions(
                    AwsAccountId=self.account_id, AnalysisId=self.asset_id
                )
                self._permissions = data["Permissions"]
            elif self.asset_type == "dataset":
                data = QS_CLIENT.describe_data_set_permissions(
                    AwsAccountId=self.account_id, DataSetId=self.asset_id
                )
                self._permissions = data["Permissions"]
            else:
                LOGGER.error("Couldn't determine asset type.")
        return self._permissions

    @property
    def dataset_ids(self) -> List[str]:
        """
        Returns List of dataset_ids used in quicksight asset (dashboard/analysis)
        """
        dataset_ids = []
        dataset_id = ""
        if self.asset_type == "dashboard":
            for arn in self.detail["Version"]["DataSetArns"]:
                try:
                    # get dataset id
                    dataset_id = arn.split("/")[1]
                    QS_CLIENT.describe_data_set(AwsAccountId=self.account_id, DataSetId=dataset_id)
                    dataset_ids.append(dataset_id)
                except ClientError as err:
                    LOGGER.error(err)
                    LOGGER.warning(
                        f"Data Set [{dataset_id}] doesn't exist. Dashboard [{self.name}] invalid."
                    )
        elif self.asset_type == "analysis":
            for arn in self.detail["DataSetArns"]:
                try:
                    # get dataset id
                    dataset_id = arn.split("/")[1]
                    QS_CLIENT.describe_data_set(AwsAccountId=self.account_id, DataSetId=dataset_id)
                    dataset_ids.append(dataset_id)
                except ClientError as err:
                    LOGGER.error(err)
                    LOGGER.warning(
                        f"Data Set [{dataset_id}] doesn't exist. Analysis [{self.name}] invalid."
                    )
        return dataset_ids

    @property
    def name(self) -> str:
        """Gets asset name"""
        return self.detail["Name"]

    @property
    def shared_namespaces(self) -> List[str]:
        """
        Gets namespaces that the dashboard is shared to
        """
        namespaces = []
        for permission in self.permissions:
            # check for group. if so add all users in that group.
            if 'namespace' in permission['Principal']:
                namespace = permission['Principal'].split("/")[-1]
                namespaces.append(namespace)
        return namespaces

    @property
    def shared_groups(self):
        """
        Gets groups that dashboard is shared to
        """
        groups = []
        for permission in self.permissions:
            # check for group. if so add all users in that group.
            if 'group' in permission['Principal']:
                group = permission['Principal'].split("/")[-1]
                namespace = permission['Principal'].split("/")[-2]
                group_obj = {"name": group, "namespace": namespace}
                groups.append(group_obj)
        return groups

    @property
    def shared_users(self) -> List[str]:
        """
        Gets users that dashboard is shared to
        """
        users = []
        for permission in self.permissions:
            if 'user' in permission['Principal']:
                username = "/".join(permission["Principal"].split("/")[-2::])
                if "Conduit" not in username:
                    users.append(username)
        return users

    @property
    def owner_emails(self) -> List[str]:
        """
        Gets owners of asset
        """
        owners = []
        for permission in self.permissions:
            if "user" in permission['Principal']:
                owner_email = permission["Principal"].split("/")[-1]
                if self.asset_type == "dashboard":
                    if QS_DASHBOARD_ADMIN_ACTION in permission["Actions"]:
                        owners.append(owner_email)
                elif self.asset_type == "analysis":
                    if QS_ANALYSIS_ADMIN_ACTION in permission["Actions"]:
                        owners.append(owner_email)
                elif self.asset_type == "dataset":
                    if QS_DATA_SET_ADMIN_ACTION in permission["Actions"]:
                        owners.append(owner_email)
        return owners

    def grant_user(self, username):
        """
        Grants permissions for user
        """
        for permission in self.permissions:
            if username in permission["Principal"]:
                LOGGER.info("Granting permissions for user '%s'", username)
                if self.asset_type == "dashboard":
                    QS_CLIENT.update_dashboard_permissions(
                        AwsAccountId=self.account_id,
                        DashboardId=self.asset_id,
                        GrantPermissions=[permission],
                    )
                elif self.asset_type == "analysis":
                    QS_CLIENT.update_analysis_permissions(
                        AwsAccountId=self.account_id,
                        AnalysisId=self.asset_id,
                        GrantPermissions=[permission],
                    )
                elif self.asset_type == "dataset":
                    QS_CLIENT.update_data_set_permissions(
                        AwsAccountId=self.account_id,
                        DataSetId=self.asset_id,
                        GrantPermissions=[permission],
                    )

    def revoke_user(self, user: QuicksightUser, permissions_needed: Set[str]) -> None:
        """
        Handles user inadequate asset permissions based on table permissions needed
        """
        warning_msg = (
            f"AssetGovernance: User [{user.username}] does not have "
            f"permissions for {self.asset_type}: {self.name}. \n"
            f"Table permissions needed: {str(permissions_needed)}. \n"
            f"{self.asset_type} owners: {str(self.owner_emails)}. \n"
            f"Asset ID: {self.asset_id}"
        )
        LOGGER.warning(warning_msg)
        email_owners(self.owner_emails, warning_msg)
        notify_slack_report(warning_msg)

        for permission in self.permissions:
            if user.username in permission["Principal"]:
                LOGGER.info("Revoking permissions for user '%s'", user.username)
                if self.asset_type == "dashboard":
                    QS_CLIENT.update_dashboard_permissions(
                        AwsAccountId=self.account_id,
                        DashboardId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "analysis":
                    QS_CLIENT.update_analysis_permissions(
                        AwsAccountId=self.account_id,
                        AnalysisId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "dataset":
                    QS_CLIENT.update_data_set_permissions(
                        AwsAccountId=self.account_id,
                        DataSetId=self.asset_id,
                        RevokePermissions=[permission],
                    )

    def revoke_group(self, group, permissions_needed: Set[str]) -> None:
        """
        Handles group inadequate dashboard permissions based on table permissions needed
        """
        warning_msg = (
            f"AssetGovernance: A user in Group {group['name']} "
            f"lacks permissions to {self.asset_type}: {self.name}. \n"
            f"Table permissions needed: {str(permissions_needed)}. \n"
            f"{self.asset_type} owners: {str(self.owner_emails)}. \n"
            f"Asset ID: {self.asset_id}"
        )
        LOGGER.warning(warning_msg)

        email_owners(self.owner_emails, warning_msg)
        notify_slack_report(warning_msg)

        for permission in self.permissions:
            if group['name'] in permission["Principal"]:
                LOGGER.info("Revoking permissions for group '%s'", group['name'])
                if self.asset_type == "dashboard":
                    QS_CLIENT.update_dashboard_permissions(
                        AwsAccountId=self.account_id,
                        DashboardId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "analysis":
                    QS_CLIENT.update_analysis_permissions(
                        AwsAccountId=self.account_id,
                        AnalysisId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "dataset":
                    QS_CLIENT.update_data_set_permissions(
                        AwsAccountId=self.account_id,
                        DataSetId=self.asset_id,
                        RevokePermissions=[permission],
                    )

        # reapply permissions for dashboard owners
        for username in self.owner_emails:
            self.grant_user(username)

    def revoke_namespace(self, namespace, permissions_needed: Set[str]) -> None:
        """
        Handles namespace inadequate asset permissions based on table permissions needed
        """
        warning_msg = (
            f"AssetGovernance: A user in Namespace {namespace} "
            f"lacks permissions to {self.asset_type}: {self.name}. \n"
            f"Table permissions needed: {str(permissions_needed)}. \n"
            f"{self.asset_type} owners: {str(self.owner_emails)}. \n"
            f"Asset ID: {self.asset_id}"
        )

        LOGGER.warning(warning_msg)
        email_owners(self.owner_emails, warning_msg)
        notify_slack_report(warning_msg)

        for permission in self.permissions:
            if namespace in permission["Principal"]:
                LOGGER.info("Revoking permissions for namespace '%s'", namespace)
                if self.asset_type == "dashboard":
                    QS_CLIENT.update_dashboard_permissions(
                        AwsAccountId=self.account_id,
                        DashboardId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "analysis":
                    QS_CLIENT.update_analysis_permissions(
                        AwsAccountId=self.account_id,
                        AnalysisId=self.asset_id,
                        RevokePermissions=[permission],
                    )
                elif self.asset_type == "dashboard":
                    QS_CLIENT.update_data_set_permissions(
                        AwsAccountId=self.account_id,
                        DataSetId=self.asset_id,
                        RevokePermissions=[permission],
                    )
        # reapply permissions for dashboard owners
        for username in self.owner_emails:
            self.grant_user(username)

    # -------------------------------
    # Data Set Specific functions
    # -------------------------------

    def get_athena_tables(self, existing_glue_databases: List[str]) -> List[str]:
        """
        Returns list of athena tables in dataset
        """
        tables = []
        if self.asset_type == "dataset":
            for table_hash, table_data in self.detail["PhysicalTableMap"].items():
                for table_type, table_details in table_data.items():
                    if table_type == "RelationalTable":
                        tables.append(f"{table_details['Schema']}.{table_details['Name']}")
                    elif table_type == "CustomSql":
                        tables.extend(
                            list(
                                QuickSightAsset.parse_tables_from_sql(
                                    table_details["SqlQuery"], existing_glue_databases
                                )
                            )
                        )
        return tables

    @staticmethod
    def parse_tables_from_sql(sql_query: str, existing_database_names: List[str]) -> Iterator[str]:
        """Parses tables from sql"""
        split = sql_query.split(" ")
        for segment in split:
            # If segment starts with any database in existing databases, classify as athena table
            if "." in segment and any(
                segment.startswith(existing_database_name)
                for existing_database_name in existing_database_names
            ):
                yield segment


def handler(event, context):
    """
    Handler: Runs QuickSight Asset Policing

    1) Gets all Quicksight Datasets, Dashboards, Policy/Group manifests from s3,
       and Okta user documents from s3
    2) Identify all table permissions per user based on group membership
    3) For each dashboard, analysis, and dataset, Infer athena tables used
    4) if user does not have access to all athena tables, then handle inadequate
       permissions
    """

    try:
        # if event is scoped to single dashboard then `dashboards` is a single item list
        # else scan all
        LOGGER.info(event)
        account_id = boto3.client("sts").get_caller_identity().get("Account")
        datasets = {
            dataset_id: QuickSightAsset(account_id, dataset_id, "dataset")
            for dataset_id in get_all_dataset_ids(account_id)
        }
        dashboards = [
            QuickSightAsset(account_id, dashboard_id, "dashboard")
            for dashboard_id in get_all_dashboard_ids(account_id)
        ]

        analyses = [
            QuickSightAsset(account_id, analysis_id, "analysis")
            for analysis_id in get_all_analysis_ids(account_id)
        ]

        groups: Dict[str, QuicksightGroupConfig] = get_all_groups()
        users: List[QuicksightUser] = get_all_users()
        # Get user table permissions based on group membership
        for user in users.values():
            user.set_table_grants(groups)

        existing_glue_databases = [
            database["Name"] for database in boto3.client("glue").get_databases()["DatabaseList"]
        ]

        LOGGER.info("Beginning QuickSight Dashboard Asset Governance...")

        for dashboard in dashboards:
            perform_governance(dashboard, account_id, datasets, users, existing_glue_databases)

        LOGGER.info("Beginning QuickSight Analysis Asset Governance...")

        for analysis in analyses:
            perform_governance(analysis, account_id, datasets, users, existing_glue_databases)

        LOGGER.info("Beginning QuickSight Data Set Asset Governance...")

        for dataset_id in datasets:
            dataset = datasets[dataset_id]
            perform_governance(dataset, account_id, datasets, users, existing_glue_databases)

        return SUCCESS_RESPONSE

    except Exception as err:
        LOGGER.error(traceback.format_exc())
        notify_slack_failure(context, traceback.format_exc())
        raise Exception(FAILURE_RESPONSE) from err


def perform_governance(asset, account_id, datasets, users, existing_glue_databases):
    """
    1) Scan asset and retrieve shared groups, namespaces, users.
    2) Determine if those groups/namespaces/users have appropriate permissions
    3) if not, revoke them.
    """
    LOGGER.info(f"Scanning {asset.asset_type}: {asset.name}; Id={asset.asset_id}")
    # Get all athena tables used across all datasets in asset

    asset_tables_used = set()

    if asset.asset_type in ['analysis', 'dashboard']:
        asset_tables_used = set(
            table
            for dataset_id in asset.dataset_ids
            for table in datasets[dataset_id].get_athena_tables(existing_glue_databases)
        )
    elif asset.asset_type == 'dataset':
        asset_tables_used = set(
            table for table in datasets[asset.asset_id].get_athena_tables(existing_glue_databases)
        )

    if asset_tables_used:

        LOGGER.info("Tables used %s", str(asset_tables_used))

        # Evaluate QuickSight groups that have been shared this asset
        for shared_group in asset.shared_groups:
            members = get_group_memberships(
                shared_group['name'], account_id, shared_group['namespace']
            )
            for username in members:
                user_obj = users[username]
                table_permissions_needed = asset_tables_used - user_obj.table_permissions
                if table_permissions_needed:
                    break
            if table_permissions_needed:
                asset.revoke_group(shared_group, table_permissions_needed)
            else:
                LOGGER.info(
                    "Group %s has adequate permissions for '%s' '%s'",
                    shared_group,
                    asset.asset_type,
                    asset.name,
                )

        # Evaluate QuickSight Namespaces that have been shared this asset
        for shared_namespace in asset.shared_namespaces:
            for user in users:
                user_obj = users[user]
                table_permissions_needed = asset_tables_used - user_obj.table_permissions
                if table_permissions_needed:
                    break
            if table_permissions_needed:
                asset.revoke_namespace(shared_namespace, table_permissions_needed)
            else:
                LOGGER.info(
                    "Namespace %s has adequate permissions for '%s' '%s'",
                    shared_namespace,
                    asset.asset_type,
                    asset.name,
                )

        # Evaluate QuickSight Users that have been shared this asset
        for shared_username in asset.shared_users:
            user_obj = users[shared_username]
            table_permissions_needed = asset_tables_used - user_obj.table_permissions
            if table_permissions_needed:
                asset.revoke_user(user_obj, table_permissions_needed)
            else:
                LOGGER.info(
                    "User %s has adequate permissions for '%s' '%s'",
                    shared_username,
                    asset.asset_type,
                    asset.name,
                )


def get_policy_configs(bucket, key) -> Dict[str, QuicksightGroupConfig]:
    """
    Retrieve manifest file and generate dict of asset objects
    """
    data = S3_CLIENT.get_object(Bucket=bucket, Key=key)
    json_data = json.loads(data["Body"].read().decode("utf-8"))
    policies = json_data["policies"]
    return {policy["group"]: QuicksightGroupConfig(**policy) for policy in policies}


def get_all_dataset_ids(account_id) -> List[str]:
    """
    Paginate through all list_data_sets responses and build a list of every
    dataset in the QuickSight account.
    """
    dset_ids = []
    response = QS_CLIENT.list_data_sets(AwsAccountId=account_id)
    for dset in response["DataSetSummaries"]:
        dset_ids.append(dset["DataSetId"])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_data_sets(
            AwsAccountId=account_id, NextToken=response.get("NextToken")
        )
        for dset in response["DataSetSummaries"]:
            dset_ids.append(dset["DataSetId"])
    return dset_ids


def get_all_dashboard_ids(account_id) -> List[str]:
    """
    Paginate through all list_dashboards responses and build a list of every
    dashboard in the QuickSight account.
    """
    dashboard_ids = []
    response = QS_CLIENT.list_dashboards(AwsAccountId=account_id)
    for dboard in response["DashboardSummaryList"]:
        dashboard_ids.append(dboard["DashboardId"])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_dashboards(
            AwsAccountId=account_id, NextToken=response.get("NextToken")
        )
        for dboard in response["DashboardSummaryList"]:
            dashboard_ids.append(dboard["DashboardId"])
    return dashboard_ids


def get_all_analysis_ids(account_id) -> List[str]:
    """
    Paginate through all list_analyses responses and build a list of every
    analysis in the QuickSight account.
    """
    analysis_ids = []
    response = QS_CLIENT.list_analyses(AwsAccountId=account_id)
    for analysis in response["AnalysisSummaryList"]:
        if analysis['Status'] != 'DELETED':
            analysis_ids.append(analysis["AnalysisId"])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_analyses(
            AwsAccountId=account_id, NextToken=response.get("NextToken")
        )
        for analysis in response["AnalysisSummaryList"]:
            if analysis['Status'] != 'DELETED':
                analysis_ids.append(analysis["AnalysisId"])
    return analysis_ids


def get_all_users() -> List[QuicksightUser]:
    """
    Gets Okta user info from S3
    """
    objs = S3_CLIENT.list_objects_v2(Bucket=BUCKET, Prefix=S3_PREFIX_USERS, MaxKeys=1000)[
        "Contents"
    ]
    keys = [obj["Key"] for obj in objs]
    users = {}
    for key in keys:
        data = json.loads(
            S3_CLIENT.get_object(Bucket=BUCKET, Key=key)["Body"].read().decode("utf-8")
        )
        user = QuicksightUser(**data)
        users[user.username] = user
    LOGGER.info(users)
    return users


def get_all_groups():
    """
    Gets all groups configs from s3 as mapping of group name to database / table access
    """
    objs = S3_CLIENT.list_objects_v2(Bucket=BUCKET, Prefix=S3_PREFIX_POLICIES, MaxKeys=1000)[
        "Contents"
    ]
    keys = [obj["Key"] for obj in objs]
    groups = {}
    for key in keys:
        data = json.loads(
            S3_CLIENT.get_object(Bucket=BUCKET, Key=key)["Body"].read().decode("utf-8")
        )
        for policy in data["policies"]:
            databases = [GroupDatabaseConfig(**database) for database in policy["databases"]]
            groups[policy["group"]] = QuicksightGroupConfig(
                group=policy["group"], namespace=policy["namespace"], databases=databases
            )
    LOGGER.info(groups)
    return groups


def get_group_memberships(group, account_id, namespace):
    """
    Get all user memberships for one group
    """

    members = []

    response = QS_CLIENT.list_group_memberships(
        GroupName=group, AwsAccountId=account_id, Namespace=namespace
    )
    for member in response["GroupMemberList"]:
        members.append(member["MemberName"])
    while response.get("NextToken", None) is not None:
        response = QS_CLIENT.list_group_memberships(
            GroupName=group,
            AwsAccountId=account_id,
            Namespace=namespace,
            NextToken=response.get("NextToken"),
        )
        for member in response["GroupMemberList"]:
            members.append(member["MemberName"])

    return members


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


def email_owners(owners, message):
    """
    Send an email to the Admins/Owners of a QuickSight Asset.
    """

    for owner in owners:
        try:
            if "@amazon.com" not in owner:
                recipient = owner + "@amazon.com"
            else:
                recipient = owner
            sender = VERIFIED_EMAIL
            subject = "QuickSight Asset Governance Alert"
            body_text = message
            body_html = """<html>
                            <head></head>
                            <body>
                            <h1>QuickSight Data Core Permission Notice</h1>
                            <p>
                            {message}
                            </p>
                            </body>
                            </html>
                        """.format(
                message=message
            )

            charset = "UTF-8"

            response = SES_CLIENT.send_email(
                Source=sender,
                Destination={
                    'ToAddresses': [
                        recipient,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': charset,
                            'Data': body_html,
                        },
                        'Text': {
                            'Charset': charset,
                            'Data': body_text,
                        },
                    },
                    'Subject': {
                        'Charset': charset,
                        'Data': subject,
                    },
                },
            )
        # Display an error if something goes wrong.
        except ClientError as err:
            LOGGER.error(err.response['Error']['Message'])
        else:
            msg_id = response['MessageId']
            LOGGER.info(f"Email sent to asset owner! Message ID: {msg_id}")


if __name__ == "__main__":
    handler({}, {})
