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

	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	h "github.com/jonhadfield/ape/helpers"
	"github.com/pkg/errors"
)

type kmsKey struct {
	region             string
	KeyArn             string
	KeyID              string
	KeyRotationEnabled bool
	Managed            string
	Failure            error
}

var allKmsKeysByAccountID map[string][]kmsKey
var noKmsKeysByAccountID map[string]bool

// func handleAWSKmsError(input error, region string) (err error) {
//	if awsErr, isAWSErr := input.(awserr.Error); isAWSErr {
//		// Get error details
//		switch awsErr.Code() {
//		case "UnrecognizedClientException":
//			err = awsErr
//			return
//		case "MissingRegion":
//			err = awsErr
//			return
//		case "AccessDeniedException":
//			err = awsErr
//			return
//		default:
//			err = errors.Wrapf(awsErr, "unhandled exception getting keys for region: %s", region)
//			return
//		}
//	}
//	return
// }

var kmsClientByAccountAndRegion map[string]kmsiface.KMSAPI
var kmsClientByAccountAndRegionMutex sync.Mutex

func getKMSClient(session *session.Session, accID, region string) (output kmsiface.KMSAPI) {
	kmsClientByAccountAndRegionMutex.Lock()
	if kmsClientByAccountAndRegion == nil {
		kmsClientByAccountAndRegion = make(map[string]kmsiface.KMSAPI)
	}
	if len(kmsClientByAccountAndRegion) == 0 {
		kmsClientByAccountAndRegion = make(map[string]kmsiface.KMSAPI)
	}
	if kmsClientByAccountAndRegion[accID+region] != nil {
		output = kmsClientByAccountAndRegion[accID+region]
	} else {
		output = kms.New(session, aws.NewConfig().WithRegion(region))
		kmsClientByAccountAndRegion[accID+region] = output
	}
	kmsClientByAccountAndRegionMutex.Unlock()
	return
}

func loadKeys(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	h.Debug(l, "loading kms keys")
	if allKmsKeysByAccountID == nil {
		allKmsKeysByAccountID = make(map[string][]kmsKey)
	}
	if noKmsKeysByAccountID == nil {
		noKmsKeysByAccountID = make(map[string]bool)
	}

	var ch = make(chan error)
	var allKmsKeysByAccountIDMutex sync.Mutex
	for _, region := range regions {
		go func(region string) {
			var routineErr error
			svc := getKMSClient(session, accountID, region)
			var listKeysInput kms.ListKeysInput
			var listKeysOutput *kms.ListKeysOutput
			listKeysOutput, routineErr = svc.ListKeys(&listKeysInput)
			if routineErr != nil {
				routineErr = errors.WithStack(routineErr)
				h.Error(l, routineErr.Error())
				ch <- routineErr
				return
			}
			kmsKeys := listKeysOutput.Keys
			for _, key := range kmsKeys {
				describeKeyInput := kms.DescribeKeyInput{KeyId: key.KeyId}
				var describeKeyOutput *kms.DescribeKeyOutput
				describeKeyOutput, routineErr = svc.DescribeKey(&describeKeyInput)
				if routineErr != nil {
					routineErr = errors.WithStack(routineErr)
					ch <- routineErr
					return

				}
				var keyRotationEnabled bool
				var keyManaged string
				if describeKeyOutput.KeyMetadata.KeyManager != nil && *describeKeyOutput.KeyMetadata.KeyManager == "CUSTOMER" {
					keyManaged = "CUSTOMER"
					var getKeyRotationStatusInput = &kms.GetKeyRotationStatusInput{KeyId: key.KeyId}
					var rotationStatusOutput *kms.GetKeyRotationStatusOutput
					rotationStatusOutput, routineErr = svc.GetKeyRotationStatus(getKeyRotationStatusInput)
					if routineErr != nil {
						routineErr = errors.WithStack(routineErr)
					} else {
						if rotationStatusOutput.KeyRotationEnabled != nil && *rotationStatusOutput.KeyRotationEnabled {
							keyRotationEnabled = true
						}
					}
				} else {
					keyManaged = "AWS"
					keyRotationEnabled = true
				}
				allKmsKeysByAccountIDMutex.Lock()
				allKmsKeysByAccountID[accountID] = append(allKmsKeysByAccountID[accountID], kmsKey{
					region:             region,
					KeyArn:             *key.KeyArn,
					KeyID:              *key.KeyId,
					KeyRotationEnabled: keyRotationEnabled,
					Managed:            keyManaged,
				})
				allKmsKeysByAccountIDMutex.Unlock()
			}
			ch <- routineErr
		}(region)
	}
	for i := 1; i <= len(regions); i++ {
		out := <-ch
		if out != nil {
			err = out
			return
		}
	}
	return
}

func filterCustomerManaged(key kmsKey, value string) (filterMatch bool) {
	if key.Managed == "CUSTOMER" && value == "true" {
		filterMatch = true
	} else if key.Managed == "AWS" && value == "false" {
		filterMatch = true
	}
	return
}

func filterKeyRotationEnabled(key kmsKey, value string) (filterMatch bool) {
	if key.KeyRotationEnabled && value == "true" {
		filterMatch = true
	} else if !key.KeyRotationEnabled && value == "false" {
		filterMatch = true
	}
	return
}

func processKMSErrors(l []interface{}, err error, planItem PlanItem) (outputErr policyItemOutputError) {
	h.Debug(l, "processing KMS errors")
	if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
		_, resource, _ := h.GetResourceParts(planItem.Policy.Resource)
		switch resource {
		case "Key":
			if strings.Contains(awsErr.Message(), "kms:ListKeys") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"kms:ListKeys\" to run this policy", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "kms:GetKeyRotationStatus") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"kms:GetKeyRotationStatus\" to run this policy", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "kms:DescribeKey") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"kms:DescribeKey\" to run this policy", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		}
	} else {
		outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
	}

	return
}

func enforceKmsPolicy(l []interface{},
	session *session.Session, planItem PlanItem) (output enforcePolicyOutput, err error) {
	var outputErr policyItemOutputError
	// if there are no keys loaded for this account, but we've not tried to load them before...
	if len(allKmsKeysByAccountID[planItem.Target.AccountID]) < 1 && !noKmsKeysByAccountID[planItem.Target.AccountID] {
		// then try loading keys for this account
		err = loadKeys(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr = processKMSErrors(l, err, planItem)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}
	}
	var filtersMatch, anyFiltersMatch bool
	var keys = allKmsKeysByAccountID[planItem.Target.AccountID]

	for _, key := range keys {
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{key.KeyArn, key.KeyID},
			itemRegion:  key.region,
		}) {
			continue
		}
		for _, filter := range planItem.Policy.Filters {
			var filterMatch bool
			switch filter.Criterion {
			case "KeyRotationEnabled":
				filterMatch = filterKeyRotationEnabled(key, filter.Value)
			case "CustomerManaged":
				filterMatch = filterCustomerManaged(key, filter.Value)
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
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:    planItem,
						ResourceArn: key.KeyArn,
						IssuesFound: issuesFound,
						Region:      key.region,
					})
				}
			}
		}

	}
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}
