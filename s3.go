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

	"golang.org/x/net/context"

	"encoding/json"
	"net/url"

	"strings"

	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	rs "github.com/jonhadfield/ape/root/aws/s3"
	"github.com/pkg/errors"
)

var s3SClientByAccountAndRegion map[string]*s3.S3

func getActualBucketRegion(l []interface{}, session *session.Session, s3BucketName string, homeRegion string) (region string, err error) {
	ctx := context.Background()
	region, err = s3manager.GetBucketRegion(ctx, session, s3BucketName, homeRegion)
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

var s3SClientByAccountAndRegionMutex sync.Mutex

func getS3Client(l []interface{}, session *session.Session, accID string, actualRegion string) (output *s3.S3) {
	s3SClientByAccountAndRegionMutex.Lock()
	if s3SClientByAccountAndRegion == nil {
		h.Debug(l, "initialising s3client cache")
		s3SClientByAccountAndRegion = make(map[string]*s3.S3)
	}
	if s3SClientByAccountAndRegion[accID+actualRegion] != nil {
		h.Debug(l, "initialising s3client cache")
		output = s3SClientByAccountAndRegion[accID+actualRegion]
	} else {
		// TODO: don't default to Ireland - determine somehow or allow override
		var useRegion string
		if actualRegion != "" {
			useRegion = actualRegion
		} else {
			useRegion = "eu-west-1"
		}
		output = s3.New(session, aws.NewConfig().WithRegion(useRegion))
		s3SClientByAccountAndRegion[accID+actualRegion] = output
	}
	s3SClientByAccountAndRegionMutex.Unlock()
	return
}

func enforceS3Policy(l []interface{}, session *session.Session, planItem PlanItem) (result enforcePolicyOutput, err error) {
	var resource string
	_, resource, err = h.GetResourceParts(planItem.Policy.Resource)
	if err != nil {
		return
	}
	switch resource {
	case "Bucket":
		result, err = enforceS3BucketPolicy(l, session, planItem)
	default:
		err = errors.Errorf("unhandled resource: s3:%s", resource)
	}
	return
}

func getLoggingForBucket(l []interface{}, svc s3iface.S3API, s3BucketName string) (result *s3.GetBucketLoggingOutput, err error) {
	input := s3.GetBucketLoggingInput{
		Bucket: &s3BucketName,
	}
	result, err = svc.GetBucketLogging(&input)
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func unmarshallS3ResourcesFromPolicyStatement(ps rs.StatementEntry) (resources []string, err error) {
	var singleResource string
	var multipleResources []string
	err = json.Unmarshal(ps.Resource, &singleResource)
	if err != nil {
		// if unable to unmarshall as a single resource
		// try to unmarshall as multipleResources
		err = json.Unmarshal(ps.Resource, &multipleResources)
		if err != nil {
			// if unable to unmarshall as multiple resources either, then return
			err = errors.WithStack(err)
			return
		}
		resources = append(resources, multipleResources...)

	} else {
		resources = append(resources, singleResource[:])
	}
	return
}

func unmarshallS3ActionsFromPolicyStatement(ps rs.StatementEntry) (actions []string, err error) {
	var singleAction string
	var multipleActions []string
	err = json.Unmarshal(ps.Action, &singleAction)
	if err != nil {
		err = json.Unmarshal(ps.Action, &multipleActions)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		actions = append(actions, multipleActions...)
	} else {
		actions = append(actions, singleAction[:])
	}
	return
}

func parseBucketPolicy(document string) (statements []rs.PolicyStatement, err error) {
	var policyDocument rs.PolicyDocument
	var decodedDocument string
	decodedDocument, err = url.QueryUnescape(document)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	err = json.Unmarshal([]byte(decodedDocument), &policyDocument)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	rawStatements := string(policyDocument.Statement[:])
	var policyStatements []rs.StatementEntry
	err = json.Unmarshal([]byte(rawStatements), &policyStatements)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	var principals string
	var resources []string
	var actions []string

	for _, ps := range policyStatements {
		// *** PRINCIPALS
		if string(ps.Principal[:]) != "" {
			principals = string(ps.Principal[:])
		}
		// *** RESOURCES
		if string(ps.Resource[:]) != "" {
			resources, err = unmarshallS3ResourcesFromPolicyStatement(ps)
			if err != nil {
				err = errors.WithStack(err)
				return
			}
		}
		// *** ACTIONS
		if string(ps.Action[:]) != "" {
			actions, err = unmarshallS3ActionsFromPolicyStatement(ps)
			if err != nil {
				err = errors.WithStack(err)
				return
			}
		}
		var pse = rs.PolicyStatement{
			Principal: principals,
			Effect:    ps.Effect,
			Resource:  resources,
			Action:    actions,
		}
		statements = append(statements, pse)
	}
	return
}

func getBucketPolicy(svc s3iface.S3API, s3BucketName string) (policy []rs.PolicyStatement, err error) {
	getBucketPolicyInput := &s3.GetBucketPolicyInput{Bucket: &s3BucketName}
	var getBucketPolicyOutput *s3.GetBucketPolicyOutput
	getBucketPolicyOutput, err = svc.GetBucketPolicy(getBucketPolicyInput)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	rawPolicy := *getBucketPolicyOutput.Policy
	if rawPolicy != "" {
		policy, err = parseBucketPolicy(rawPolicy)
		if err != nil {
			return
		}
	}
	return
}

func getBucketACL(svc s3iface.S3API, s3BucketName string) ([]*s3.Grant, error) {
	getBucketACLInput := &s3.GetBucketAclInput{Bucket: &s3BucketName}
	getBucketACLOutput, err := svc.GetBucketAcl(getBucketACLInput)
	if err != nil {
		err = errors.WithStack(err)
	}
	return getBucketACLOutput.Grants, err
}

var allBucketsByAccount map[string][]bucket

var noBucketsByAccount map[string]bool

type bucket struct {
	// region string
	owner  s3.Owner
	bucket s3.Bucket
}

func loadBuckets(l []interface{}, svc s3iface.S3API, accountID string) (err error) {
	h.Debug(l, "loading buckets")
	if allBucketsByAccount == nil {
		allBucketsByAccount = make(map[string][]bucket)
	}
	if noBucketsByAccount == nil {
		noBucketsByAccount = make(map[string]bool)
	}
	var listBucketsOutput *s3.ListBucketsOutput
	listBucketsOutput, err = svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	for _, bucketItem := range listBucketsOutput.Buckets {
		allBucketsByAccount[accountID] = append(allBucketsByAccount[accountID], bucket{bucket: *bucketItem, owner: *listBucketsOutput.Owner})
	}

	if len(allBucketsByAccount[accountID]) == 0 {
		noBucketsByAccount[accountID] = true
	}
	return
}

func checkS3BucketPublicAccessByACL(grants []*s3.Grant) (result bool) {
	var badUrls = []string{"http://acs.amazonaws.com/groups/global/AllUsers",
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}
	for _, grant := range grants {
		if *grant.Grantee.Type == "Group" && h.StringInSlice(*grant.Grantee.URI, badUrls) {
			result = true
			break
		}
	}
	return
}

func checkS3BucketPublicAccessByPolicy(policy []rs.PolicyStatement) (result bool) {
	for _, statement := range policy {
		if statement.Effect == "Allow" && statement.Principal == "\"*\"" {
			result = true
			break
		}
	}
	return
}

func filterCheckPublicAccess(grants []*s3.Grant, policy []rs.PolicyStatement, filter r.Filter) (filterMatch bool, err error) {
	var failedACL, failedPolicy bool
	if checkS3BucketPublicAccessByACL(grants) {
		failedACL = true
	}
	if checkS3BucketPublicAccessByPolicy(policy) {
		failedPolicy = true
	}

	if filter.Value == "false" && (!failedACL && !failedPolicy) {
		filterMatch = true
	} else if filter.Value == "true" && (failedACL || failedPolicy) {
		filterMatch = true
	}
	return
}

type isIgnoredInput struct {
	planItem    PlanItem
	resourceIDs []string
	itemRegion  string
}

func isIgnored(i isIgnoredInput) (result bool) {
	// get slice of ignored items if defined
	if len(i.planItem.ignoredResources) == 0 {
		return
	}
	var wildcard = []string{"", "*"}
	for _, ir := range i.planItem.ignoredResources {
		// check for account match (blank == match all)
		if h.StringInSlice(ir.AccountID, wildcard) || (i.planItem.Target.AccountID == ir.AccountID) {
			// check for region match
			if h.StringInSlice(ir.Region, wildcard) || i.itemRegion == ir.Region {
				// check for service match
				service, resource, _ := h.GetResourceParts(i.planItem.Policy.Resource)
				if h.StringInSlice(ir.Service, wildcard) || service == ir.Service {
					// check for resource match
					if h.StringInSlice(ir.Resource, wildcard) || resource == ir.Resource {
						// check for ids match
						if h.StringInSlice(ir.ID, wildcard) || h.StringInSlice(ir.ID, i.resourceIDs) {
							result = true
							return
						}
					}
				}
			}

		}
	}
	return
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func logPolicyOutputItemError(l []interface{}, item policyItemOutputError) {
	var output string
	if item.error != nil {
		errS, okS := item.error.(stackTracer)
		if okS {
			var errParts []string
			for _, f := range errS.StackTrace() {
				errParts = append(errParts, fmt.Sprintf("%+s:%d\n", f, f))
				output = item.message + "\n" + strings.Join(errParts, "")
			}
		} else {
			output = item.message + "\n" + item.error.Error()
		}
	}

	switch item.level {
	case "debug":
		h.Debug(l, output)
	case "info":
		h.Info(l, output)
	case "warn":
		h.Warn(l, output)
	case "error":
		h.Error(l, output)
	case "critical":
		h.Critical(l, output)
	}
}

func processS3Errors(l []interface{}, err error, planItem PlanItem, msgOveride map[string]string) (outputErr policyItemOutputError) {
	h.Debug(l, "processing S3 errors")
	if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
		_, resource, _ := h.GetResourceParts(planItem.Policy.Resource)
		switch resource {
		case "Bucket":
			if msgOveride != nil {
				outputErr = policyItemOutputError{message: msgOveride[awsErr.Code()], error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		}
	} else {
		outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
	}

	return
}

func enforceS3BucketPolicy(l []interface{}, session *session.Session, planItem PlanItem) (output enforcePolicyOutput, err error) {
	var svc *s3.S3
	var outputErr policyItemOutputError
	svc = getS3Client(l, session, planItem.Target.AccountID, "eu-west-1")
	if len(allBucketsByAccount[planItem.Target.AccountID]) < 1 && !noBucketsByAccount[planItem.Target.AccountID] {
		err = loadBuckets(l, svc, planItem.Target.AccountID)
		if err != nil {
			msgOverride := map[string]string{
				"AccessDenied": "failed: missing required permission \"s3:ListAllMyBuckets\"",
			}
			outputErr = processS3Errors(l, err, planItem, msgOverride)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}
	}
	var failuresEncountered, anyFiltersMatch bool
bucket:
	for _, bucketItem := range allBucketsByAccount[planItem.Target.AccountID] {
		outputErr = policyItemOutputError{}
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*bucketItem.bucket.Name},
			itemRegion:  "",
		}) {
			continue
		}
		var filterMatch, filtersMatch bool

		for _, filter := range planItem.Policy.Filters {
			switch filter.Criterion {
			case "AllowsPublicAccess":
				var result bool
				var actualRegion string
				actualRegion, err = getActualBucketRegion(l, session, *bucketItem.bucket.Name, "eu-west-1")
				if err != nil {
					// handle error if bucket region can't be discovered
					failuresEncountered = true
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem: planItem,
						OutputErr: policyItemOutputError{
							message: fmt.Sprintf("failed to get region for: arn:aws:s3:::%s", *bucketItem.bucket.Name),
							level:   "error",
							error:   err,
						},
						IssuesFound: true,
					})
					continue bucket
				}
				if s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion] == nil {
					s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion] = getS3Client(l, session, planItem.Target.AccountID, actualRegion)
				}
				var bucketGrants []*s3.Grant
				bucketGrants, err = getBucketACL(s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion], *bucketItem.bucket.Name)
				if err != nil {
					failuresEncountered = true
					// handle error if bucket ACL can't be read
					if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
						// Get error details
						switch awsErr.Code() {
						case "AccessDenied":
							outputErr.message = fmt.Sprintf("failed: missing required permission \"s3:GetBucketACL\" on \"%s\"", *bucketItem.bucket.Name)
							outputErr.level = "error"
							outputErr.error = err
						default:
							outputErr.message = fmt.Sprintf("failed: unhandled exception getting ACL for: arn:aws:s3:::%s", *bucketItem.bucket.Name)
							outputErr.level = "error"
							outputErr.error = err
						}
					}
					outputErr.error = err
					logPolicyOutputItemError(l, outputErr)
					// include the stack trace
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:    planItem,
						OutputErr:   outputErr,
						IssuesFound: true,
					})
					// can continue in any case, as there's no way of continuing filter if ACL can't be retrieved
					continue bucket
				}

				var bucketPolicy []rs.PolicyStatement
				bucketPolicy, err = getBucketPolicy(s3SClientByAccountAndRegion[planItem.Target.AccountID+actualRegion], *bucketItem.bucket.Name)
				if err != nil {
					failuresEncountered = true
					if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
						// Get error details
						switch awsErr.Code() {
						case "AccessDenied":
							outputErr.message = fmt.Sprintf("failed: missing required permission \"s3:GetBucketPolicy\" on \"%s\"", *bucketItem.bucket.Name)
							outputErr.level = "error"
							outputErr.error = err
							output = appendPolicyOutput(l, output, createPolicyOutputInput{
								PlanItem:    planItem,
								OutputErr:   outputErr,
								IssuesFound: true,
							})
							logPolicyOutputItemError(l, outputErr)
							continue bucket
						case "NoSuchBucketPolicy":
							outputErr.message = fmt.Sprintf("ok: no bucket policy exists for: \"%s\"", *bucketItem.bucket.Name)
							outputErr.level = "debug"
							outputErr.error = err
							failuresEncountered = false
							logPolicyOutputItemError(l, outputErr)
						default:
							outputErr.message = fmt.Sprintf("failed: unhandled exception getting policy on: \"%s\"", *bucketItem.bucket.Name)
							outputErr.level = "error"
							outputErr.error = err
							output = appendPolicyOutput(l, output, createPolicyOutputInput{
								PlanItem:    planItem,
								OutputErr:   outputErr,
								IssuesFound: true,
							})
							logPolicyOutputItemError(l, outputErr)
							continue bucket
						}
					}
				}

				result, err = filterCheckPublicAccess(bucketGrants, bucketPolicy, filter)
				if filter.Value == "true" && result {
					filterMatch = true
				} else if filter.Value == "false" && !result {
					filterMatch = true
				}
			default:
				err = fmt.Errorf("criterion: \"%s\" is not implemented, yet exists in catalogue. Oops", filter.Criterion)
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
						PlanItem:     planItem,
						ResourceName: *bucketItem.bucket.Name,
						ResourceArn:  *bucketItem.bucket.Name,
						IssuesFound:  issuesFound,
					})
				}
			}
		}
	}
	if !anyFiltersMatch && !failuresEncountered {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}
