### IAM policy for CIS foundations

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudwatch:DescribeAlarms",
                "config:DescribeConfigurationRecorders",
                "config:DescribeDeliveryChannels",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetLoginProfile",
                "iam:GetPolicyVersion",
                "iam:ListAccountAliases",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListMFADevices",
                "iam:ListPolicies",
                "iam:ListPolicyVersions",
                "iam:ListUsers",
                "iam:ListVirtualMFADevices",
                "iam:ListRoles",
                "iam:ListUserPolicies",
                "kms:GetKeyRotationStatus",
                "kms:ListKeys",
                "kms:DescribeKey",
                "logs:DescribeMetricFilters",
                "s3:GetBucketAcl",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "SNS:ListSubscriptionsByTopic"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```