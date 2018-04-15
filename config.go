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
	"strings"

	"fmt"

	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/pkg/errors"
)

var allConfigsByAccount map[string]configs

var noConfigsByAccount map[string]bool

type configs []configItem

type configItem struct {
	region          string
	recorder        *configservice.ConfigurationRecorder
	deliveryChannel *configservice.DeliveryChannel
	missing         bool
	failure         error
}

func loadConfigServiceItems(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	if noConfigsByAccount[accountID] {
		return
	}

	var configItems configs
	var configItemsMutex sync.Mutex
	var ch = make(chan error)
	for _, region := range regions {
		go func(region string) {
			var routineErr error
			h.Debug(l, fmt.Sprintf("loading config for region: %s\n", region))
			svc := configservice.New(session, aws.NewConfig().WithRegion(region))
			describeConfigurationRecordersInput := configservice.DescribeConfigurationRecordersInput{}
			describeDeliveryChannelsInput := configservice.DescribeDeliveryChannelsInput{}
			// get recorders
			var describeConfigurationRecordersOutput *configservice.DescribeConfigurationRecordersOutput
			describeConfigurationRecordersOutput, routineErr =
				svc.DescribeConfigurationRecorders(&describeConfigurationRecordersInput)
			if routineErr != nil {
				routineErr = errors.WithStack(routineErr)
			} else {
				var recorder configservice.ConfigurationRecorder
				// if recorders returned, then set
				if len(describeConfigurationRecordersOutput.ConfigurationRecorders) > 0 {
					recorder = *describeConfigurationRecordersOutput.ConfigurationRecorders[0]
					var describeDeliveryChannelsOutput *configservice.DescribeDeliveryChannelsOutput
					describeDeliveryChannelsOutput, routineErr = svc.DescribeDeliveryChannels(&describeDeliveryChannelsInput)
					if routineErr != nil {
						routineErr = errors.WithStack(routineErr)
					} else {
						var deliveryChannel configservice.DeliveryChannel
						if len(describeDeliveryChannelsOutput.DeliveryChannels) > 0 {
							deliveryChannel = *describeDeliveryChannelsOutput.DeliveryChannels[0]
							configItemsMutex.Lock()
							configItems = append(configItems, configItem{
								region:          region,
								deliveryChannel: &deliveryChannel,
								recorder:        &recorder,
							})
							configItemsMutex.Unlock()
						} else {
							configItemsMutex.Lock()
							configItems = append(configItems, configItem{
								region:  region,
								missing: true,
							})
							configItemsMutex.Unlock()
						}
					}
				} else {
					configItemsMutex.Lock()
					configItems = append(configItems, configItem{
						region:  region,
						missing: true,
					})
					configItemsMutex.Unlock()
				}
			}
			ch <- routineErr
		}(region)
	}
	for i := 1; i <= len(regions); i++ {
		err = <-ch
		if err != nil {
			return
		}
	}
	allConfigsByAccount[accountID] = configItems
	if len(allConfigsByAccount[accountID]) == 0 {
		noConfigsByAccount[accountID] = true
	}
	return
}

func enforceConfigPolicy(l []interface{}, session *session.Session,
	planItem PlanItem) (output enforcePolicyOutput, err error) {
	var outputErr policyItemOutputError
	if allConfigsByAccount == nil {
		allConfigsByAccount = make(map[string]configs)
	}
	var filtersMatch bool
	var failuresEncountered bool
	var anyFiltersMatch bool
	if len(allConfigsByAccount[planItem.Target.AccountID]) == 0 {
		err = loadConfigServiceItems(l, session, planItem.Target.AccountID, planItem.Target.Regions)
	}
	if err != nil {
		if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
			if strings.Contains(awsErr.Message(), "config:DescribeConfigurationRecorders") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"config:DescribeConfigurationRecorders\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "config:DescribeDeliveryChannels") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"config:DescribeDeliveryChannels\"", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		} else {
			outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
		}
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: true,
			OutputErr:   outputErr,
		})
		logPolicyOutputItemError(l, outputErr)
		return
	}

	for _, config := range allConfigsByAccount[planItem.Target.AccountID] {
		if config.recorder != nil {
			if isIgnored(isIgnoredInput{
				planItem:    planItem,
				resourceIDs: []string{*config.recorder.Name},
				itemRegion:  config.region,
			}) {
				continue
			}
		}
		if config.failure != nil {
			h.Warn(l, config.failure.Error())
			failuresEncountered = true
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				Message:     fmt.Sprintf("failed to read Config in region: %s", config.region),
				IssuesFound: true,
			})
			continue
		}
		for _, filter := range planItem.Policy.Filters {
			var filterMatch bool
			switch filter.Criterion {
			case "AllSupportedResourceTypes":
				filterMatch = filterAllSupportedResourceTypes(filter, config)
			case "IncludeGlobalResourceTypes":
				filterMatch = filterIncludeGlobalResourceTypes(filter, config)
			case "DeliveryChannelS3BucketNameDefined":
				filterMatch = filterDeliveryChannelS3BucketNameDefined(filter, config)

			case "DeliveryChannelSnsTopicARNDefined":
				filterMatch = filterDeliveryChannelSnsTopicARNDefined(filter, config)
			}
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
			// All filters match for this user, so perform all actions
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
					if config.missing {
						output = appendPolicyOutput(l, output, createPolicyOutputInput{
							PlanItem:    planItem,
							Message:     fmt.Sprintf("missing in: %s", config.region),
							IssuesFound: issuesFound,
						})
					} else {
						output = appendPolicyOutput(l, output, createPolicyOutputInput{
							PlanItem:     planItem,
							ResourceName: *config.recorder.Name + " (" + config.region + ")",
							IssuesFound:  issuesFound,
						})
					}
				}
			}
		}

	}
	if !anyFiltersMatch && !failuresEncountered {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}

func filterAllSupportedResourceTypes(filter r.Filter, config configItem) (filterMatch bool) {
	if config.missing {
		if filter.Value == "false" {
			filterMatch = true
		}
	} else {
		supported := *config.recorder.RecordingGroup.AllSupported
		if supported && filter.Value == "true" || !supported && filter.Value == "false" {
			filterMatch = true
		}
	}
	return
}

func filterIncludeGlobalResourceTypes(filter r.Filter, config configItem) (filterMatch bool) {
	if config.missing {
		if filter.Value == "false" {
			filterMatch = true
		}
	} else {
		if config.recorder.RecordingGroup != nil {
			includeGlobal := *config.recorder.RecordingGroup.IncludeGlobalResourceTypes
			if includeGlobal && filter.Value == "true" || !includeGlobal && filter.Value == "false" {
				filterMatch = true
			}
		}
	}
	return
}

func filterDeliveryChannelS3BucketNameDefined(filter r.Filter, config configItem) (filterMatch bool) {
	if config.missing {
		if filter.Value == "false" {
			filterMatch = true
		}
	} else {
		var bucketDefined bool
		if config.deliveryChannel.S3BucketName != nil && *config.deliveryChannel.S3BucketName != "" {
			bucketDefined = true

		}
		if filter.Value == "true" && bucketDefined {
			filterMatch = true
		}
		if filter.Value == "false" && !bucketDefined {
			filterMatch = true
		}
	}
	return
}

func filterDeliveryChannelSnsTopicARNDefined(filter r.Filter, config configItem) (filterMatch bool) {
	if config.missing {
		if filter.Value == "false" {
			filterMatch = true
		}

	} else {
		var arnDefined bool
		if config.deliveryChannel.SnsTopicARN != nil && *config.deliveryChannel.SnsTopicARN != "" {
			arnDefined = true

		}
		if filter.Value == "true" && arnDefined {
			filterMatch = true
		}
		if filter.Value == "false" && !arnDefined {
			filterMatch = true
		}
	}
	return
}
