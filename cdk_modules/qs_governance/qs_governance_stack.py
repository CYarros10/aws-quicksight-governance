"""
AWS CDK Stack to deploy QuickSight Governance solution in an AWS Account.
Consists of:
    - S3 Bucket
    - ListRoles IAM Policy
    - Federated QuickSight IAM Policy + Role
    - OktaSSOUser IAM User
    - Lambda Layer
    - 4 Lambda Functions + IAM Policy
    - 2 S3 Event Sources
    - 1 Event Rule
    - 2 S3 Deployments
"""

import os
import subprocess as sp
from aws_cdk import (
    aws_athena as athena,
    aws_iam as iam,
    aws_s3 as s3,
    aws_lambda as _lambda,
    aws_lambda_event_sources as lambda_event_sources,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_s3_deployment as s3_deploy,
    core,
)
import config as cf


class QSGovernanceStack(core.Stack):
    """
    AWS CDK Stack to deploy QuickSight Governance solution in an AWS Account
    """

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        """
        initialize function for CDK
        """
        super().__init__(scope, construct_id, **kwargs)

        # -------------------------------
        # S3 Bucket for Manifests
        # -------------------------------

        qs_gov_bucket = s3.Bucket(
            self,
            id=f"{cf.PROJECT}-Bucket",
        )
        bucket_name = qs_gov_bucket.bucket_name

        # -------------------------------
        # IAM
        # -------------------------------

        list_roles_policy = iam.ManagedPolicy(
            self,
            id=f"{cf.PROJECT}-ListRolesPolicy",
            managed_policy_name=f"{cf.PROJECT}-ListRolesPolicy",
            description=None,
            path="/",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=["iam:ListRoles", "iam:ListAccountAliases"],
                )
            ],
        )

        federated_quicksight_policy = iam.ManagedPolicy(
            self,
            id=f"{cf.PROJECT}-FederatedQuickSightPolicy",
            managed_policy_name=f"{cf.PROJECT}-FederatedQuickSightPolicy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:iam::{cf.ACCOUNT}:saml-provider/{cf.OKTA_IDP_NAME}"
                    ],
                    actions=["sts:AssumeRoleWithSAML"],
                    conditions={
                        "StringEquals": {
                            "saml:aud": "https://signin.aws.amazon.com/saml"
                        }
                    },
                )
            ],
        )

        okta_federated_principal = iam.FederatedPrincipal(
            federated=f"arn:aws:iam::{cf.ACCOUNT}:saml-provider/{cf.OKTA_IDP_NAME}",
            assume_role_action="sts:AssumeRoleWithSAML",
            conditions={
                "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
            },
        )

        federated_quicksight_role = iam.Role(
            self,
            id=f"{cf.PROJECT}-{cf.QS_FEDERATED_ROLE_NAME}",
            role_name=f"{cf.QS_FEDERATED_ROLE_NAME}",
            assumed_by=okta_federated_principal,
            description="Allow Okta to Federate Login & User Creation to QuickSight",
            managed_policies=[federated_quicksight_policy],
        )


        iam.User(
            self,
            id=f"{cf.PROJECT}-OktaSSOUser",
            user_name=f"{cf.PROJECT}-OktaSSOUser",
            managed_policies=[list_roles_policy],
        )

        # -------------------------------
        # Lambda Layers
        # -------------------------------

        path_src = os.path.join(cf.PATH_SRC, "")

        sp.call(["make", "bundle"], cwd=path_src)

        requests_layer = _lambda.LayerVersion(
            self,
            f"{cf.PROJECT}-requests-layer",
            code=_lambda.Code.from_asset(
                os.path.join(path_src, "requests.zip")
            )
        )

        sp.call(["make", "clean"], cwd=path_src)

        # -------------------------------
        # Lambda Functions
        # -------------------------------

        # iam role for Lambdas

        qs_governance_policy = iam.ManagedPolicy(
            self,
            id=f"{cf.PROJECT}-LambdaPolicy",
            managed_policy_name=f"{cf.PROJECT}-LambdaPolicy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "*"
                    ],
                    actions=[
                        "ses:SendEmail",
                        "ses:SendRawEmail"
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:secretsmanager:{cf.REGION}:{cf.ACCOUNT}:secret:{cf.OKTA_SECRET_ID}*",
                        f"arn:aws:secretsmanager:{cf.REGION}:{cf.ACCOUNT}:secret:{cf.SLACK_SECRET_ID}*"
                    ],
                    actions=[
                        "secretsmanager:GetSecretValue",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:iam::{cf.ACCOUNT}:policy/{cf.QS_PREFIX}*"
                    ],
                    actions=[
                        "iam:CreatePolicy",
                        "iam:GetPolicy",
                        "iam:DeletePolicy",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "*"
                    ],
                    actions=[
                        "iam:ListPolicies"
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "glue:GetDatabase",
                        "glue:GetDatabases",
                        "glue:GetTable",
                        "glue:GetPartitions",
                        "glue:GetPartition",
                        "glue:GetTables",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=["quicksight:*", "ds:*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:s3:::{bucket_name}/*",f"arn:aws:s3:::{bucket_name}*"],
                    actions=["s3:*"],
                ),
            ],
        )

        qs_governance_role = iam.Role(
            self,
            id=f"{cf.PROJECT}-QuickSightPermissionMappingRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                qs_governance_policy,
            ],
        )

        # Lambdas

        get_okta_information_lambda = _lambda.Function(
            self,
            id=f"{cf.PROJECT}-GetOktaInfo",
            function_name=f"{cf.PROJECT}-GetOktaInformation",
            handler="get_okta_information.handler",
            role=qs_governance_role,
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset(os.path.join(cf.PATH_SRC, "pkg")),
            environment={
                "OKTA_SECRET_ID": cf.OKTA_SECRET_ID,
                "QS_PREFIX": cf.QS_PREFIX,
                "QS_GOVERNANCE_BUCKET": bucket_name,
                "QS_FEDERATED_ROLE_NAME": f"{cf.QS_FEDERATED_ROLE_NAME}",
                "S3_PREFIX_USERS": cf.S3_PREFIX_USERS,
                "SLACK_SECRET_ID": cf.SLACK_SECRET_ID
            },
            memory_size=256,
            timeout=core.Duration.seconds(180),
            layers=[requests_layer],
        )

        # Lamda Okta to QuickSight Mappers

        qs_user_governance_lambda = _lambda.Function(
            self,
            id=f"{cf.PROJECT}-QSUserGovernance",
            function_name=f"{cf.PROJECT}-QSUserGovernance",
            handler="qs_user_governance.handler",
            role=qs_governance_role,
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset(os.path.join(cf.PATH_SRC, "pkg")),
            environment={
                "QS_FEDERATED_ROLE_NAME": f"{cf.QS_FEDERATED_ROLE_NAME}",
                "QS_PREFIX": cf.QS_PREFIX,
                "QS_ADMIN_OKTA_GROUP": cf.QS_ADMIN_OKTA_GROUP,
                "QS_AUTHOR_OKTA_GROUP": cf.QS_AUTHOR_OKTA_GROUP,
                "QS_READER_OKTA_GROUP": cf.QS_READER_OKTA_GROUP,
                "SLACK_SECRET_ID": cf.SLACK_SECRET_ID
            },
            memory_size=256,
            timeout=core.Duration.seconds(180),
            layers=[requests_layer],
        )


        qs_asset_governance_lambda = _lambda.Function(
            self,
            id=f"{cf.PROJECT}-QSAssetGovernance",
            function_name=f"{cf.PROJECT}-QSAssetGovernance",
            handler="qs_asset_governance.handler",
            role=qs_governance_role,
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset(os.path.join(cf.PATH_SRC, "pkg")),
            memory_size=256,
            timeout=core.Duration.seconds(180),
            layers=[requests_layer],
            environment={
                "QS_GOVERNANCE_BUCKET": f"{bucket_name}",
                "S3_PREFIX_USERS": cf.S3_PREFIX_USERS,
                "S3_PREFIX_POLICIES": cf.S3_PREFIX_POLICIES,
                "STAGE": cf.DEPLOYMENT_STAGE,
                "SLACK_SECRET_ID": cf.SLACK_SECRET_ID,
                "VERIFIED_EMAIL": cf.VERIFIED_EMAIL
            }
        )

        qs_policy_governance_lambda = _lambda.Function(
            self,
            id=f"{cf.PROJECT}-QSPolicyGovernance",
            function_name=f"{cf.PROJECT}-QSPolicyGovernance",
            handler="qs_policy_governance.handler",
            role=qs_governance_role,
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset(os.path.join(cf.PATH_SRC, "pkg")),
            environment={
                "QS_ADMIN_OKTA_GROUP": cf.QS_ADMIN_OKTA_GROUP,
                "QS_AUTHOR_OKTA_GROUP": cf.QS_AUTHOR_OKTA_GROUP,
                "QS_AUTHOR_BASE_POLICY": cf.QS_AUTHOR_BASE_POLICY,
                "QS_PREFIX": cf.QS_PREFIX,
                "QS_GOVERNANCE_BUCKET": f"{bucket_name}",
                "S3_PREFIX_POLICIES": cf.S3_PREFIX_POLICIES,
                "QS_SUPERUSER": cf.QS_SUPERUSER,
                "DEPLOYMENT_STAGE": cf.DEPLOYMENT_STAGE,
                "SLACK_SECRET_ID": cf.SLACK_SECRET_ID
            },
            memory_size=256,
            timeout=core.Duration.seconds(180),
            layers=[requests_layer]
        )

        qs_resource_cleanup_lambda = _lambda.Function(
            self,
            id=f"{cf.PROJECT}-QSResourceCleanup",
            function_name=f"{cf.PROJECT}-QSResourceCleanup",
            handler="qs_resource_cleanup.handler",
            role=qs_governance_role,
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset(os.path.join(cf.PATH_SRC, "pkg")),
            memory_size=256,
            timeout=core.Duration.seconds(180),
            layers=[requests_layer],
            environment={
                "QS_PREFIX": cf.QS_PREFIX,
                "QS_SUPERUSER": cf.QS_SUPERUSER,
                "QS_GOVERNANCE_BUCKET": f"{bucket_name}",
                "S3_PREFIX_ASSETS": cf.S3_PREFIX_ASSETS,
                "S3_PREFIX_USERS": cf.S3_PREFIX_USERS,
                "S3_PREFIX_POLICIES": cf.S3_PREFIX_POLICIES,
                "SLACK_SECRET_ID": cf.SLACK_SECRET_ID
            }
        )

        # -------------------------------
        # S3 Event Triggers
        # -------------------------------

        qs_user_governance_lambda.add_event_source(
            lambda_event_sources.S3EventSource(
                bucket=qs_gov_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix=cf.S3_PREFIX_USERS)],
            )
        )

        qs_policy_governance_lambda.add_event_source(
            lambda_event_sources.S3EventSource(
                bucket=qs_gov_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix=cf.S3_PREFIX_POLICIES)],
            )
        )

        # -------------------------------
        # CloudWatch Event Rules (30 minutes)
        # -------------------------------

        lambda_schedule = events.Schedule.rate(core.Duration.minutes(30))
        get_okta_info_target = events_targets.LambdaFunction(
            handler=get_okta_information_lambda
        )
        events.Rule(
            self,
            id=f"{cf.PROJECT}-GetOktaInfoScheduledEvent",
            description="The scheduled CloudWatch event trigger for the Lambda",
            enabled=True,
            schedule=lambda_schedule,
            targets=[get_okta_info_target],
        )

        qs_asset_gov_target = events_targets.LambdaFunction(
            handler=qs_asset_governance_lambda
        )
        events.Rule(
            self,
            id=f"{cf.PROJECT}-QSAssetGovScheduledEvent",
            description="The scheduled CloudWatch event trigger for the Lambda",
            enabled=True,
            schedule=lambda_schedule,
            targets=[qs_asset_gov_target],
        )

        qs_cleanup_target = events_targets.LambdaFunction(
            handler=qs_resource_cleanup_lambda
        )
        events.Rule(
            self,
            id=f"{cf.PROJECT}-QSCleanupScheduledEvent",
            description="The scheduled CloudWatch event trigger for the Lambda",
            enabled=True,
            schedule=lambda_schedule,
            targets=[qs_cleanup_target],
        )

        # -------------------------------
        # Athena WorkGroup
        # -------------------------------

        workgroup_encryption = athena.CfnWorkGroup.EncryptionConfigurationProperty(
            encryption_option='SSE_S3'
        )

        workgroup_output = athena.CfnWorkGroup.ResultConfigurationProperty(
            output_location="s3://"+cf.ATHENA_OUTPUT_LOC,
            encryption_configuration=workgroup_encryption
        )


        quicksight_athena_workgroup = athena.CfnWorkGroup(
            self,
            id=f"{cf.PROJECT}-workgroup",
            name=f"{cf.QS_PREFIX}-workgroup",
            description="workgroup for QuickSight Data Source operations",
            recursive_delete_option=True,
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=workgroup_output
            )
        )
        workgroup_name = quicksight_athena_workgroup.name

        # -------------------------------
        # S3 Object Deployments
        # -------------------------------

        policy_manifest_deploy = s3_deploy.BucketDeployment(
            self,
            id=f"{cf.PROJECT}-PolicyManifestDeploy",
            sources=[s3_deploy.Source.asset(
                os.path.join(cf.PATH_ROOT, "qs_config/policies")
            )],
            destination_bucket=qs_gov_bucket,
            destination_key_prefix=cf.S3_PREFIX_POLICIES
        )

        # -------------------------------
        # QuickSight IAM Policy Assignments
        # -------------------------------

        qs_author_base_policy = iam.ManagedPolicy(
            self,
            id=f"{cf.PROJECT}-{cf.QS_AUTHOR_BASE_POLICY}",
            managed_policy_name=f"{cf.QS_AUTHOR_BASE_POLICY}",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:athena:{cf.REGION}:{cf.ACCOUNT}:workgroup/{workgroup_name}"
                    ],
                    actions=[
                        "athena:GetNamedQuery",
                        "athena:CancelQueryExecution",
                        "athena:CreateNamedQuery",
                        "athena:DeleteNamedQuery",
                        "athena:StartQueryExecution",
                        "athena:StopQueryExecution",
                        "athena:GetWorkGroup",
                        "athena:GetNamedQuery",
                        "athena:GetQueryResults",
                        "athena:GetQueryExecution",
                        "athena:BatchGetQueryExecution",
                        "athena:BatchGetNamedQuery",
                        "athena:ListNamedQueries",
                        "athena:ListQueryExecutions",
                        "athena:GetQueryResultsStream"
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "*"
                    ],
                    actions=[
                        "athena:ListWorkGroups",
                        "athena:ListDataCatalogs",
                        "athena:StartQueryExecution",
                        "athena:GetQueryExecution",
                        "athena:GetQueryResultsStream",
                        "athena:ListTableMetadata",
                        "athena:GetTableMetadata"
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "arn:aws:s3:::ast-datalake-*",
                        "arn:aws:s3:::aws-athena-query-*",
                        f"arn:aws:s3:::{bucket_name}*",
                        f"arn:aws:s3:::{cf.ATHENA_OUTPUT_LOC}*"
                    ],
                    actions=[
                        "s3:List*",
                        "s3:Get*",
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "*"
                    ],
                    actions=[
                        "s3:ListAllMyBuckets"
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "arn:aws:s3:::aws-athena-query-*",
                        f"arn:aws:s3:::{bucket_name}/{cf.QS_PREFIX}/athena-results*"
                    ],
                    actions=[
                        "s3:Put*"
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:athena:{cf.REGION}:{cf.ACCOUNT}:datacatalog/AwsDataCatalog"
                    ],
                    actions=[
                        "athena:ListDatabases"
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        "*"
                    ],
                    actions=[
                        "kms:Decrypt",
                        "kms:GenerateDataKey"
                    ]
                ),
            ],
        )