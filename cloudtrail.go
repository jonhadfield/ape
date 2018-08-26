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

package ape

import (
	"fmt"

	"strings"

	"time"

	"sync"

	"github.com/Knetic/govaluate"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	rs "github.com/jonhadfield/ape/root/aws/s3"
	"github.com/pkg/errors"
)

var cloudtrailClientByAccountAndRegion map[string]cloudtrailiface.CloudTrailAPI
var cloudtrailClientByAccountAndRegionMutex sync.Mutex

func getCloudtrailClient(l []interface{}, session *session.Session, accID, region string) (output cloudtrailiface.CloudTrailAPI) {
	h.Debug(l, fmt.Sprintf("getting cloudtrail client for: %s", accID))
	cloudtrailClientByAccountAndRegionMutex.Lock()
	if cloudtrailClientByAccountAndRegion == nil {
		cloudtrailClientByAccountAndRegion = make(map[string]cloudtrailiface.CloudTrailAPI)
	}
	if len(cloudtrailClientByAccountAndRegion) == 0 {
		cloudtrailClientByAccountAndRegion = make(map[string]cloudtrailiface.CloudTrailAPI)
	}
	if cloudtrailClientByAccountAndRegion[accID+region] != nil {
		output = cloudtrailClientByAccountAndRegion[accID+region]
	} else {
		output = cloudtrail.New(session, aws.NewConfig().WithRegion(region))
		cloudtrailClientByAccountAndRegion[accID+region] = output
	}
	cloudtrailClientByAccountAndRegionMutex.Unlock()
	return
}

func processCloudtrailErrors(l []interface{}, err error, planItem PlanItem) (outputErr policyItemOutputError) {
	h.Debug(l, "processing cloudtrail errors")
	if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
		_, resource, _ := h.GetResourceParts(planItem.Policy.Resource)
		switch resource {
		case "Trail":
			if strings.Contains(awsErr.Message(), "cloudtrail:DescribeTrails") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"cloudtrail:DescribeTrails\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "SNS:ListSubscriptionsByTopic") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"SNS:ListSubscriptionsByTopic\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "logs:DescribeMetricFilters") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"logs:DescribeMetricFilters\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "cloudtrail:GetTrailStatus") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"cloudtrail:GetTrailStatus\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Code(), "MethodNotAllowed") {
				outputErr = policyItemOutputError{message: "failed: unable to check CloudTrail events bucket permissions as it's not owned by this account", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "cloudwatch:DescribeAlarms") {
				outputErr = policyItemOutputError{message: "failed: missing permission \"cloudwatch:DescribeAlarms\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Code(), "AccessDenied") {
				outputErr = policyItemOutputError{message: "failed: unable to check CloudTrail events bucket - check permissions", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		}
	} else {
		outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
	}
	return
}

func enforceCloudTrailPolicy(l []interface{}, session *session.Session, planItem PlanItem) (result enforcePolicyOutput, err error) {
	var resource string
	_, resource, err = h.GetResourceParts(planItem.Policy.Resource)
	if err != nil {
		return
	}
	switch resource {
	case "Trail":
		result, err = enforceTrailPolicy(l, session, planItem)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("unhandled resource: iam:%s", resource)
	}
	return
}

func describeTrails(svc cloudtrailiface.CloudTrailAPI) (trails []*cloudtrail.Trail, err error) {
	var output *cloudtrail.DescribeTrailsOutput
	output, err = svc.DescribeTrails(&cloudtrail.DescribeTrailsInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	trails = append(trails, output.TrailList...)
	return
}

var allTrailsByAccount map[string][]cloudtrailTrail

var noTrailsByAccount map[string]bool

type cloudtrailTrail struct {
	region string
	trail  cloudtrail.Trail
}

var allTrailsByAccountMutex sync.Mutex

func loadTrails(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	if allTrailsByAccount == nil {
		allTrailsByAccount = make(map[string][]cloudtrailTrail)
	}
	if noTrailsByAccount == nil {
		noTrailsByAccount = make(map[string]bool)
	}
	numRegions := len(regions)
	var ch = make(chan error)
	for _, region := range regions {
		svc := getCloudtrailClient(l, session, accountID, region)
		go func(region string) {
			var routineErr error
			h.Debug(l, fmt.Sprintf("loading trails for account: %s region: %s\n", accountID, region))
			var trails []*cloudtrail.Trail
			trails, routineErr = describeTrails(svc)
			if routineErr == nil {
				for _, trail := range trails {
					if *trail.HomeRegion == region {
						allTrailsByAccountMutex.Lock()
						allTrailsByAccount[accountID] = append(allTrailsByAccount[accountID], cloudtrailTrail{
							region: region,
							trail:  *trail,
						})
						allTrailsByAccountMutex.Unlock()
					}
				}
			}
			ch <- routineErr
		}(region)
	}
	for i := 1; i <= numRegions; i++ {
		err = <-ch
		if err != nil {
			return
		}
	}
	if len(allTrailsByAccount[accountID]) == 0 {
		noTrailsByAccount[accountID] = true
	}
	return
}

func filterLatestCloudWatchLogsDeliveryTime(svc cloudtrailiface.CloudTrailAPI, trail cloudtrail.Trail, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	var filterValue time.Time
	filterValue, err = r.ProcessTimeFilterValue(filter)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	var trailStatus *cloudtrail.GetTrailStatusOutput
	trailStatus, err = svc.GetTrailStatus(&cloudtrail.GetTrailStatusInput{
		Name: trail.Name,
	})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	// Check if LatestCloudWatchLogsDeliveryTime > or < date
	lastDeliveryOutput := trailStatus.LatestCloudWatchLogsDeliveryTime
	if lastDeliveryOutput == nil || lastDeliveryOutput.IsZero() {
		// if we're trying to match on delivery being older than, and they've never
		// been delivered, then it is a match
		if filter.Comparison == ">" {
			filterMatch = true
		}
	} else {
		lastDelivery := lastDeliveryOutput.In(loc)
		expressionTxt := fmt.Sprintf("(filterValue %s lastDelivered)", filter.Comparison)
		expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
		parameters := make(map[string]interface{}, 8)
		parameters["lastDelivered"] = lastDelivery.Unix()
		parameters["filterValue"] = filterValue.Unix()
		var result interface{}
		result, err = expression.Evaluate(parameters)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		if result == true {
			filterMatch = true
		}
	}
	return
}

type filterBucketLoggingEnabledInput struct {
	session      *session.Session
	planItem     PlanItem
	trail        *cloudtrailTrail
	filter       *r.Filter
	mockS3Client s3iface.S3API
}

func filterBucketLoggingEnabled(l []interface{}, input filterBucketLoggingEnabledInput) (filterMatch bool, err error) {
	s3BucketName := *input.trail.trail.S3BucketName
	var bucketLogging *s3.GetBucketLoggingOutput
	var actualRegion string
	var s3Client s3iface.S3API
	if input.session != nil {
		actualRegion, err = getActualBucketRegion(l, input.session, s3BucketName, *input.trail.trail.HomeRegion)
		if err != nil {
			return
		}
		s3Client = getS3Client(l, input.session, input.planItem.Target.AccountID, actualRegion)
	} else {
		s3Client = input.mockS3Client
	}
	bucketLogging, err = getLoggingForBucket(l, s3Client, s3BucketName)
	if err != nil {
		return
	}
	var loggingEnabled bool
	if bucketLogging.LoggingEnabled != nil {
		loggingEnabled = true
	}
	if input.filter.Value == "true" && loggingEnabled {
		filterMatch = true
	}
	if input.filter.Value == "false" && !loggingEnabled {
		filterMatch = true
	}
	return
}

func getMetricFiltersByPatternAndLogGroupName(pattern, logGroupName string, cwlSvc cloudwatchlogsiface.CloudWatchLogsAPI) (filters []*cloudwatchlogs.MetricFilter, err error) {
	describeMetricFiltersInput := cloudwatchlogs.DescribeMetricFiltersInput{
		LogGroupName: &logGroupName,
	}
	var describeMetricFiltersOutput *cloudwatchlogs.DescribeMetricFiltersOutput
	describeMetricFiltersOutput, err = cwlSvc.DescribeMetricFilters(&describeMetricFiltersInput)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	for _, metricFilter := range describeMetricFiltersOutput.MetricFilters {
		wantedFilter := strings.Replace(pattern, " ", "", -1)
		unspacedFilter := strings.Replace(*metricFilter.FilterPattern, " ", "", -1)
		if strings.Contains(unspacedFilter, wantedFilter) {
			filters = append(filters, metricFilter)
		}

	}
	return
}

func getSubscriptionsByTopicArn(snsSvc snsiface.SNSAPI, topicArn string) (subscriptions []*sns.Subscription, err error) {
	var listSubscriptionsByTopicInput = sns.ListSubscriptionsByTopicInput{
		TopicArn: &topicArn,
	}
	var listSubscriptionsByTopicOutput *sns.ListSubscriptionsByTopicOutput
	listSubscriptionsByTopicOutput, err = snsSvc.ListSubscriptionsByTopic(&listSubscriptionsByTopicInput)
	if err != nil {
		err = errors.WithStack(err)
	}
	subscriptions = listSubscriptionsByTopicOutput.Subscriptions
	return
}

func getMetricAlarmsByMetricName(cwSvc cloudwatchiface.CloudWatchAPI, metricName string) (metricAlarms []cloudwatch.MetricAlarm, err error) {
	var describeAlarmsInput *cloudwatch.DescribeAlarmsInput
	var describeAlarmsOutput *cloudwatch.DescribeAlarmsOutput
	describeAlarmsOutput, err = cwSvc.DescribeAlarms(describeAlarmsInput)
	if err != nil {
		err = errors.WithStack(err)
	}
	for _, alarm := range describeAlarmsOutput.MetricAlarms {
		if *alarm.MetricName == metricName {
			metricAlarms = append(metricAlarms, *alarm)
		}
	}
	return
}

func filterMetricFilterPattern(l []interface{}, cwlSvc cloudwatchlogsiface.CloudWatchLogsAPI, cwSvc cloudwatchiface.CloudWatchAPI, snsSvc *snsiface.SNSAPI, trail cloudtrailTrail, filterPattern string) (result bool, err error) {
	h.Debug(l, fmt.Sprintf("filtering by metric pattern: %s", filterPattern))
	// get cloudwatch log group
	if trail.trail.CloudWatchLogsLogGroupArn == nil {
		return
	}
	logGroupArn := *trail.trail.CloudWatchLogsLogGroupArn
	logGroupName := strings.Split(logGroupArn, ":")[6]
	// check if filter associcated with specified name
	var matchingFilters []*cloudwatchlogs.MetricFilter
	matchingFilters, err = getMetricFiltersByPatternAndLogGroupName(filterPattern, logGroupName, cwlSvc)
	if err != nil {
		return
	}
	for _, filter := range matchingFilters {
		var metricAlarms []cloudwatch.MetricAlarm
		metricAlarms, err = getMetricAlarmsByMetricName(cwSvc, *filter.MetricTransformations[0].MetricName)
		if err != nil {
			return
		}
		for i := range metricAlarms {
			for _, action := range metricAlarms[i].AlarmActions {
				var subscriptions []*sns.Subscription
				subscriptions, err = getSubscriptionsByTopicArn(*snsSvc, *action)
				if err != nil {
					return
				}
				if len(subscriptions) > 0 {
					result = true
					return
				}
			}
		}
	}
	return
}

func enforceTrailPolicy(l []interface{}, session *session.Session, planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing trail policy")
	var outputErr policyItemOutputError
	if len(allTrailsByAccount[planItem.Target.AccountID]) < 1 && !noTrailsByAccount[planItem.Target.AccountID] {
		err = loadTrails(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr = processCloudtrailErrors(l, err, planItem)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}

	}
	var anyFiltersMatch bool
	for _, trail := range allTrailsByAccount[planItem.Target.AccountID] {
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*trail.trail.Name},
			itemRegion:  trail.region,
		}) {
			continue
		}
		cwSvc := getCloudwatchClient(l, session, planItem.Target.AccountID, trail.region)
		cwlSvc := getCloudwatchLogsClient(l, session, planItem.Target.AccountID, trail.region)
		snslSvc := getSNSClient(l, session, planItem.Target.AccountID, trail.region)
		var filterMatch, filtersMatch bool
		var message string
		if h.StringInSlice(trail.region, planItem.Target.Regions) || trail.region == "multi" {
			for _, filter := range planItem.Policy.Filters {
				switch filter.Criterion {
				case "HasAlarmWithSubscriberForUnauthorizedAPICalls":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail, `($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}

				case "HasAlarmWithSubscriberForConsoleSignInsWithoutMFA":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail, `($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes")`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForRootAccountUsage":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail, `$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForIAMPolicyChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail, `($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForCloudTrailConfigChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail, `($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForAWSConsoleAuthFailures":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						`($.eventName = ConsoleLogin) && ($.errorMessage = "Failedauthentication")`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}

				case "HasAlarmWithSubscriberForDisablingOrScheduledDeletionOfCMK":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						`($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForS3BucketPolicyChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						` ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication))`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForConfigChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						`($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForSecGroupChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						` ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForNACLChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						`($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForNetworkGatewayChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						` ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForRouteTableChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						`($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)`)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "HasAlarmWithSubscriberForVPCChanges":
					var exists bool
					exists, err = filterMetricFilterPattern(l, cwlSvc, cwSvc, &snslSvc, trail,
						` ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) `)
					if filter.Value == "true" && exists {
						filterMatch = true
					} else if filter.Value == "false" && !exists {
						filterMatch = true
					}
				case "LogsEncrypted":
					if filter.Value == "true" && trail.trail.KmsKeyId != nil {
						filterMatch = true
					} else if filter.Value == "false" && trail.trail.KmsKeyId == nil {
						filterMatch = true
					}
				case "IsMultiRegionTrail":
					if filter.Value == "false" && !*trail.trail.IsMultiRegionTrail {
						filterMatch = true
					} else if filter.Value == "true" && *trail.trail.IsMultiRegionTrail {
						filterMatch = true
					}
				case "LogFileValidationEnabled":
					if filter.Value == "false" && !*trail.trail.LogFileValidationEnabled {
						filterMatch = true
					} else if filter.Value == "true" && *trail.trail.LogFileValidationEnabled {
						filterMatch = true
					}
				case "LatestCloudWatchLogsDeliveryTime":
					svc := getCloudtrailClient(l, session, planItem.Target.AccountID, trail.region)
					filterMatch, err = filterLatestCloudWatchLogsDeliveryTime(svc, trail.trail, &filter)
					if err != nil {
						return
					}
				case "BucketLoggingEnabled":
					filterBucketLoggingEnabledIn := filterBucketLoggingEnabledInput{
						session:  session,
						trail:    &trail,
						filter:   &filter,
						planItem: planItem,
					}
					filterMatch, err = filterBucketLoggingEnabled(l, filterBucketLoggingEnabledIn)
				case "BucketPubliclyAccessible":
					filterMatch, _, err = filterBucketPublicallyAccessible(l, session, planItem, filter, trail, output)
				default:
					err = fmt.Errorf("criterion: '%s' is not implemented, yet exists in catalogue. Oops", filter.Criterion)
					return
				}
				if err != nil {
					outputErr = processCloudtrailErrors(l, err, planItem)
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:    planItem,
						IssuesFound: true,
						OutputErr:   outputErr,
					})
					logPolicyOutputItemError(l, outputErr)
					return
				}
				// If not found, then no point running more filters
				if !filterMatch {
					filtersMatch = false
					break
				} else {
					filtersMatch = true
				}
			}
			if filtersMatch {
				// We've got at least one set of matches
				anyFiltersMatch = true
				// All filters match for this trail, so perform all actions
				var issuesFound bool
				switch planItem.Policy.ModifyResult {
				case "reverse":
					issuesFound = false
				default:
					issuesFound = true
				}
				for _, action := range planItem.Policy.Actions {
					switch strings.ToLower(action) {
					case "report":
						output = appendPolicyOutput(l, output, createPolicyOutputInput{
							PlanItem:     planItem,
							Message:      message,
							ResourceName: *trail.trail.Name,
							ResourceArn:  *trail.trail.TrailARN,
							Region:       *trail.trail.HomeRegion,
							IssuesFound:  issuesFound,
						})
					}
				}
			}
		}
	}
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}

func filterBucketPublicallyAccessible(l []interface{}, session *session.Session, planItem PlanItem, filter r.Filter, trail cloudtrailTrail, inOutput enforcePolicyOutput) (filterMatch bool, output enforcePolicyOutput, err error) {
	h.Debug(l, "filterBucketPublicallyAccessible")
	// if this was called on behalf of another resource, we need to override in order to check for ignored resource
	planItem.Policy.Resource = "s3:Bucket"
	var resIDs = []string{*trail.trail.S3BucketName}
	if isIgnored(isIgnoredInput{planItem: planItem, resourceIDs: resIDs}) {
		return
	}

	output = inOutput
	s3BucketName := *trail.trail.S3BucketName
	// check bucket ACL grants
	var trailBucketGrants []*s3.Grant
	var actualRegion string
	actualRegion, err = getActualBucketRegion(l, session, s3BucketName, *trail.trail.HomeRegion)

	if s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion] == nil {
		_ = getS3Client(l, session, planItem.Target.AccountID, actualRegion)
		if err != nil {
			return
		}
	}
	trailBucketGrants, err = getBucketACL(s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion], s3BucketName)
	if err != nil {
		return
	}
	// TODO: The group may exist but permissions may not be enabled!
	failedACL := checkS3BucketPublicAccessByACL(trailBucketGrants)
	if filter.Value == "false" && !failedACL {
		filterMatch = true
	} else if filter.Value == "true" && failedACL {
		filterMatch = true
	}

	// check bucket policy
	var trailBucketPolicy []rs.PolicyStatement
	trailBucketPolicy, err = getBucketPolicy(s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion], s3BucketName)
	if err != nil {
		return
	}
	failedPolicy := checkS3BucketPublicAccessByPolicy(trailBucketPolicy)
	if filter.Value == "false" && !failedPolicy {
		filterMatch = true
	} else if filter.Value == "true" && failedPolicy {
		filterMatch = true
	}
	return
}
