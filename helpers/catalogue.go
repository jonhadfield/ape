// Copyright 2018, Jon Hadfield <jon@lessknown.co.uk>
// This file is part of ape.

// ape is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// ape is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with ape.  If not, see <http://www.gnu.org/licenses/>.

package helpers

type Criterion struct {
	Name        string
	Comparisons []string
	Units       []string
}

type Criteria []Criterion

type Resource struct {
	Name     string
	Criteria Criteria
}

type Resources []Resource

type Service struct {
	Name      string
	Resources []Resource
}

type Services []Service

var iamPasswordPolicy = Criteria{
	{
		Name:        "MinimumPasswordLength",
		Comparisons: []string{"<", ">", ">=", "<=", "=="},
	},
	{
		Name:        "RequireAtLeastOneUpperCaseLetter",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "RequireAtLeastOneLowerCaseLetter",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "RequireAtLeastOneNumber",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "RequireAtLeastOneNonAlphanumericCharacter",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "AllowUsersToChangeTheirOwnPassword",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "PasswordExpirationPeriod",
		Comparisons: []string{"<", ">", ">=", "<=", "=="},
		Units:       []string{"days"},
	},
	{
		Name:        "NumberOfPasswordsToRemember",
		Comparisons: []string{"<", ">", ">=", "<=", "=="},
	},
	{
		Name:        "ExpirationRequiresAdministratorReset",
		Comparisons: []string{"bool"},
	},
}

var iamRoleCriteria = Criteria{
	{
		Name:        "RoleName",
		Comparisons: []string{"in", "not in", "contains"},
	},
	{
		Name:        "HasManagedPolicyAttached",
		Comparisons: []string{"in"},
	},
}

var iamPolicyCriteria = Criteria{
	{
		Name: "Version",
	},
	{
		Name:        "Effect",
		Comparisons: []string{"==", "!=", "contains"},
	},
	{
		Name:        "Resource",
		Comparisons: []string{"==", "!=", "contains"},
	},
	{
		Name:        "Action",
		Comparisons: []string{"==", "!=", "contains"},
	},
}

var iamUserCriteria = Criteria{
	{
		Name:        "UserName",
		Comparisons: []string{"in", "not in", "!=", "=="},
	},
	{
		Name:        "HasGroup",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "DoesNotHaveGroup",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasActiveAccessKey",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasMFADevice",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasActiveAccessKeyCreatedWithUser",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasUnusedActiveAccessKey",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasPassword",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasHardwareMFADevice",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasInlinePolicies",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasManagedPolicies",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "ActiveAccessKeysLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "ActiveAccessKeysAge",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "ActiveAccessKeysLastRotated",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
}

var ec2InstanceCriteria = Criteria{
	{
		Name:        "InstanceType",
		Comparisons: []string{"in", "not in"},
	},
}

var ec2VolumeCriteria = Criteria{
	{
		Name:        "Attached",
		Comparisons: []string{"bool"},
	},
}

var ec2SecurityGroupCriteria = Criteria{
	{
		Name:        "GroupName",
		Comparisons: []string{"==", "!="},
	},
	// {
	//	Name:        "HasIngressRules",
	//	Comparisons: []string{"bool"},
	// },
	// {
	//	Name:        "HasEgressRules",
	//	Comparisons: []string{"bool"},
	// },
	{
		Name:        "HasAnyRules",
		Comparisons: []string{"bool"},
	},
	// {
	//	Name:        "InUse",
	//	Comparisons: []string{"bool"},
	// },
	{
		Name:        "IngressProtocol",
		Comparisons: []string{"==", "!=", "allows"},
	},
	{
		Name:        "IngressPort",
		Comparisons: []string{"==", "!=", "allows"},
	},
	{
		Name:        "IngressIP",
		Comparisons: []string{"==", "!=", "allows"},
	},
}

var kmsKeyCriteria = Criteria{
	{
		Name:        "KeyRotationEnabled",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "CustomerManaged",
		Comparisons: []string{"bool"},
	},
}

var cloudTrailTrailCriteria = Criteria{
	{
		Name:        "HasAlarmWithSubscriberForUnauthorizedAPICalls",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForConsoleSignInsWithoutMFA",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForRootAccountUsage",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForIAMPolicyChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForCloudTrailConfigChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForAWSConsoleAuthFailures",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForS3BucketPolicyChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForConfigChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForSecGroupChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForNACLChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForNetworkGatewayChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForRouteTableChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForVPCChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForDisablingOrScheduledDeletionOfCMK",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForS3BucketPolicyChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForConfigChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForSecGroupChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForNACLChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForNetworkGatewayChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForRouteTableChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "HasAlarmWithSubscriberForVPCChanges",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "IsMultiRegionTrail",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "LogFileValidationEnabled",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "BucketPubliclyAccessible",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "LatestcloudWatchLogsDeliveryTime",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	},
	{
		Name:        "BucketLoggingEnabled",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "LogsEncrypted",
		Comparisons: []string{"bool"},
	},
}

var configRecorderCriteria = Criteria{
	{
		Name:        "AllSupportedResourceTypes",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "IncludeGlobalResourceTypes",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "DeliveryChannelS3BucketNameDefined",
		Comparisons: []string{"bool"},
	},
	{
		Name:        "DeliveryChannelSnsTopicARNDefined",
		Comparisons: []string{"bool"},
	},
}

var ec2VpcCriteria = Criteria{
	{
		Name:        "HasEnabledFlowLog",
		Comparisons: []string{"bool"},
	},
}

var s3BucketCriteria = Criteria{
	{
		Name:        "AllowsPublicAccess",
		Comparisons: []string{"bool"},
	},
}

var iamResources Resources = []Resource{
	{
		Name:     "User",
		Criteria: iamUserCriteria,
	},
	{
		Name:     "PasswordPolicy",
		Criteria: iamPasswordPolicy,
	},
	{
		Name:     "Role",
		Criteria: iamRoleCriteria,
	},
	{
		Name:     "Policy",
		Criteria: iamPolicyCriteria,
	},
}

var kmsResources Resources = []Resource{
	{
		Name:     "Key",
		Criteria: kmsKeyCriteria,
	},
}

var ec2Resources Resources = []Resource{
	{
		Name:     "Instance",
		Criteria: ec2InstanceCriteria,
	},
	{
		Name:     "Volume",
		Criteria: ec2VolumeCriteria,
	},
	{
		Name:     "SecurityGroup",
		Criteria: ec2SecurityGroupCriteria,
	},
	{
		Name:     "Vpc",
		Criteria: ec2VpcCriteria,
	},
}

var cloudTrailResources Resources = []Resource{
	{
		Name:     "Trail",
		Criteria: cloudTrailTrailCriteria,
	},
}

var configResources Resources = []Resource{
	{
		Name:     "Recorder",
		Criteria: configRecorderCriteria,
	},
}

var s3Resources Resources = []Resource{
	{
		Name:     "Bucket",
		Criteria: s3BucketCriteria,
	},
}

var ImplementedServices = Services{
	Service{
		Name:      "iam",
		Resources: iamResources,
	},
	Service{
		Name:      "ec2",
		Resources: ec2Resources,
	},
	Service{
		Name:      "cloudtrail",
		Resources: cloudTrailResources,
	},
	Service{
		Name:      "config",
		Resources: configResources,
	},
	Service{
		Name:      "kms",
		Resources: kmsResources,
	},
	Service{
		Name:      "s3",
		Resources: s3Resources,
	},
}
