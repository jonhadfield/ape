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
	"net"
	"strings"

	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/pkg/errors"
)

var allEC2InstancesByAccount map[string][]ec2Instance
var noEC2InstancesByAccount map[string]bool
var allEC2VolumesByAccount map[string][]ec2Volume
var noEC2VolumesByAccount map[string]bool
var allEC2SecurityGroupsByAccount map[string][]ec2SecurityGroup
var noEC2SecurityGroupsByAccount map[string]bool

type ec2Instance struct {
	instance ec2.Instance
	region   string
}

type ec2Volume struct {
	volume ec2.Volume
	region string
}

type ec2SecurityGroup struct {
	securityGroup ec2.SecurityGroup
	region        string
}

func describeGroups(svc ec2iface.EC2API) (groups []*ec2.SecurityGroup, err error) {
	var describeSecurityGroupsInput *ec2.DescribeSecurityGroupsInput
	var describeSecurityGroupsOutput *ec2.DescribeSecurityGroupsOutput
	describeSecurityGroupsOutput, err = svc.DescribeSecurityGroups(describeSecurityGroupsInput)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	groups = append(groups, describeSecurityGroupsOutput.SecurityGroups...)
	return
}

func loadEC2Volumes(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	var allEC2VolumesByAccountMutex sync.Mutex
	if allEC2VolumesByAccount == nil {
		allEC2VolumesByAccount = make(map[string][]ec2Volume)
	}
	if noEC2VolumesByAccount == nil {
		noEC2VolumesByAccount = make(map[string]bool)
	}
	var ch = make(chan error)

	for _, region := range regions {
		go func(region string) {
			var routineErr error
			h.Debug(l, fmt.Sprintf("loading volumes for region: %s\n", region))
			svc := getEC2Client(session, accountID, region)
			var volumes []*ec2.Volume
			volumes, routineErr = listVolumes(svc)
			if routineErr == nil {
				for _, volume := range volumes {
					allEC2VolumesByAccountMutex.Lock()
					allEC2VolumesByAccount[accountID] = append(allEC2VolumesByAccount[accountID], ec2Volume{
						region: region,
						volume: *volume,
					})
					allEC2VolumesByAccountMutex.Unlock()
				}
			}
			ch <- errors.WithStack(routineErr)
		}(region)
	}

	for i := 1; i <= len(regions); i++ {
		err = <-ch
		if err != nil {
			return
		}
	}

	if len(allEC2VolumesByAccount[accountID]) == 0 {
		noEC2VolumesByAccount[accountID] = true
	}
	return
}

func loadEC2SecurityGroups(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	if allEC2SecurityGroupsByAccount == nil {
		allEC2SecurityGroupsByAccount = make(map[string][]ec2SecurityGroup)
	}
	if noEC2SecurityGroupsByAccount == nil {
		noEC2SecurityGroupsByAccount = make(map[string]bool)
	}
	var allEC2SecurityGroupsByAccountMutex sync.Mutex
	var ch = make(chan error)
	for _, region := range regions {
		go func(region string) {
			h.Debug(l, fmt.Sprintf("loading security groups for region: %s\n", region))
			var routineErr error
			svc := getEC2Client(session, accountID, region)
			var securityGroups []*ec2.SecurityGroup
			securityGroups, routineErr = describeGroups(svc)
			if routineErr == nil {
				for _, s := range securityGroups {
					allEC2SecurityGroupsByAccountMutex.Lock()
					allEC2SecurityGroupsByAccount[accountID] = append(allEC2SecurityGroupsByAccount[accountID], ec2SecurityGroup{
						region:        region,
						securityGroup: *s,
					})
					allEC2SecurityGroupsByAccountMutex.Unlock()
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

	if len(allEC2SecurityGroupsByAccount[accountID]) == 0 {
		noEC2SecurityGroupsByAccount[accountID] = true
	}
	return
}

func loadEC2Instances(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	if allEC2InstancesByAccount == nil {
		allEC2InstancesByAccount = make(map[string][]ec2Instance)
	}
	if noEC2InstancesByAccount == nil {
		noEC2InstancesByAccount = make(map[string]bool)
	}
	var allEC2InstancesByAccountMutex sync.Mutex
	var ch = make(chan error)
	for _, region := range regions {
		svc := getEC2Client(session, accountID, region)
		go func(region string) {
			var routineErr error
			h.Debug(l, fmt.Sprintf("loading ec2 instances for region: %s\n", region))
			var instances []*ec2.Instance
			var output *ec2.DescribeInstancesOutput
			output, routineErr = svc.DescribeInstances(&ec2.DescribeInstancesInput{})
			if routineErr == nil {
				for _, reservation := range output.Reservations {
					instances = append(instances, reservation.Instances...)
				}
				for _, instance := range instances {
					allEC2InstancesByAccountMutex.Lock()
					allEC2InstancesByAccount[accountID] = append(allEC2InstancesByAccount[accountID], ec2Instance{
						region:   region,
						instance: *instance,
					})
					allEC2InstancesByAccountMutex.Unlock()
				}
			}
			ch <- errors.WithStack(routineErr)
		}(region)
	}

	for i := 1; i <= len(regions); i++ {
		err = <-ch
		if err != nil {
			return
		}
	}

	if len(allEC2InstancesByAccount[accountID]) == 0 {
		noEC2InstancesByAccount[accountID] = true
	}
	return
}

func listVolumes(svc ec2iface.EC2API) (volumes []*ec2.Volume, err error) {
	var output *ec2.DescribeVolumesOutput
	output, err = svc.DescribeVolumes(&ec2.DescribeVolumesInput{})
	if err != nil {
		return
	}
	volumes = append(volumes, output.Volumes...)
	return
}

func enforceEC2Policy(l []interface{}, session *session.Session,
	planItem PlanItem) (output enforcePolicyOutput, err error) {
	_, resource, err := h.GetResourceParts(planItem.Policy.Resource)
	if err != nil {
		return
	}
	switch resource {
	case "Instance":
		output, err = enforceInstancePolicy(l, session, planItem)
	case "Volume":
		output, err = enforceVolumePolicy(l, session, planItem.Target.AccountID, planItem)
	case "SecurityGroup":
		output, err = enforceSecurityGroupPolicy(l, session, planItem.Target.AccountID, planItem)
	case "Vpc":
		output, err = enforceVpcPolicy(l, session, planItem)
	default:
		err = errors.Errorf("unhandled resource: ec2:%s", resource)
	}
	return
}

func processEC2Errors(l []interface{}, err error, planItem PlanItem) (outputErr policyItemOutputError) {
	h.Debug(l, "processing EC2 errors")
	if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
		_, resource, _ := h.GetResourceParts(planItem.Policy.Resource)
		switch resource {
		case "Vpc":
			if awsErr.Code() == "UnauthorizedOperation" {
				outputErr = policyItemOutputError{message: "failed: " +
					"missing required permissions", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		case "SecurityGroup":
			if strings.Contains(awsErr.Code(), "AuthFailure") {
				outputErr = policyItemOutputError{message: "failed: auth failure - " +
					"either unable to authenticate or bad region", error: err, level: "error"}
			} else if strings.Contains(awsErr.Code(), "UnauthorizedOperation") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"ec2:DescribeSecurityGroups\"", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		case "Instance":
			if strings.Contains(awsErr.Code(), "AuthFailure") {
				outputErr = policyItemOutputError{message: "failed: auth failure - " +
					"either unable to authenticate or bad region", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListPolicies") {
				outputErr =
					policyItemOutputError{message: fmt.Sprintf("failed: missing required permission "+
						"\"iam:ListPolicies\" on resource \"arn:aws:iam::%s:policy/\"",
						planItem.Target.AccountID), error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListPolicyVersions") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"iam:ListPolicyVersions\" to run this policy", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:GetPolicyVersion") {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"iam:GetPolicyVersion\" to run this policy", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		case "Volume":
			if strings.Contains(awsErr.Code(), "AuthFailure") {
				outputErr = policyItemOutputError{message: "failed: auth failure - " +
					"either unable to authenticate or bad region", error: err, level: "error"}
			} else if awsErr.Code() == "UnauthorizedOperation" {
				outputErr = policyItemOutputError{message: "failed: missing required permission " +
					"\"ec2:DescribeVolumes\"", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		}
	} else {
		outputErr = policyItemOutputError{message: "failed: unhandled resource exception", error: err, level: "error"}
	}
	return
}
func getEc2Tag(tags []*ec2.Tag, key string) (value string) {
	for _, tag := range tags {
		if *tag.Key == key {
			value = *tag.Value
		}
	}
	return
}

var ec2ClientByAccountAndRegion map[string]ec2iface.EC2API
var ec2ClientByAccountAndRegionMutex sync.Mutex

func getEC2Client(session *session.Session, accID, region string) (output ec2iface.EC2API) {
	ec2ClientByAccountAndRegionMutex.Lock()
	if ec2ClientByAccountAndRegion == nil {
		ec2ClientByAccountAndRegion = make(map[string]ec2iface.EC2API)
	}
	if len(ec2ClientByAccountAndRegion) == 0 {
		ec2ClientByAccountAndRegion = make(map[string]ec2iface.EC2API)
	}
	if ec2ClientByAccountAndRegion[accID+region] != nil {
		output = ec2ClientByAccountAndRegion[accID+region]
	} else {
		output = ec2.New(session, aws.NewConfig().WithRegion(region))
		ec2ClientByAccountAndRegion[accID+region] = output
	}
	ec2ClientByAccountAndRegionMutex.Unlock()
	return
}

func getNameTag(tags []*ec2.Tag) (value string) {
	value = getEc2Tag(tags, "Name")
	return
}
func filterVolumeAttached(volume ec2Volume, filter *r.Filter) (filterMatch bool) {
	if filter.Value == "false" {
		if len(volume.volume.Attachments) == 0 {
			filterMatch = true
			return
		}
	} else if filter.Comparison == "true" {
		if len(volume.volume.Attachments) > 0 {
			filterMatch = true
			return
		}
	}
	return
}

func enforceVolumePolicy(l []interface{},
	session *session.Session, accountID string, planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing volume policy")
	var outputErr policyItemOutputError
	if len(allEC2VolumesByAccount[planItem.Target.AccountID]) < 1 && !noEC2VolumesByAccount[planItem.Target.AccountID] {
		err = loadEC2Volumes(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr = processEC2Errors(l, err, planItem)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}
	}

	volumes := allEC2VolumesByAccount[accountID]
	// Loop through regions
	var filtersMatch bool
	var anyFiltersMatch bool
	for _, volume := range volumes {
		var filterMatch bool
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{getNameTag(volume.volume.Tags), *volume.volume.VolumeId},
			itemRegion:  volume.region,
		}) {
			continue
		}
		for _, filter := range planItem.Policy.Filters {
			switch filter.Criterion {
			case "Attached":
				filterMatch = filterVolumeAttached(volume, &filter)
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
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:     planItem,
				Region:       volume.region,
				ResourceName: getNameTag(volume.volume.Tags),
				ResourceArn:  *volume.volume.VolumeId,
				IssuesFound:  true,
			})
		}
	}
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}

type secGroupPerm struct {
	ec2.IpPermission
	ingress bool
}

func combineSecGroupPermissions(securityGroup ec2.SecurityGroup) (allSecGroupPerms []secGroupPerm,
	hasAnyRules, hasAnyIngressRules, hasAnyEgressRules bool) {
	for _, i := range securityGroup.IpPermissions {
		hasAnyRules = true
		hasAnyIngressRules = true
		var perm secGroupPerm
		perm.ingress = true
		perm.IpRanges = i.IpRanges
		perm.Ipv6Ranges = i.Ipv6Ranges
		perm.FromPort = i.FromPort
		perm.ToPort = i.ToPort
		perm.IpProtocol = i.IpProtocol
		perm.UserIdGroupPairs = i.UserIdGroupPairs
		perm.PrefixListIds = i.PrefixListIds
		allSecGroupPerms = append(allSecGroupPerms, perm)
	}
	for _, j := range securityGroup.IpPermissionsEgress {
		hasAnyRules = true
		hasAnyEgressRules = true
		var perm secGroupPerm
		perm.ingress = false
		perm.IpRanges = j.IpRanges
		perm.Ipv6Ranges = j.Ipv6Ranges
		perm.FromPort = j.FromPort
		perm.ToPort = j.ToPort
		perm.IpProtocol = j.IpProtocol
		perm.UserIdGroupPairs = j.UserIdGroupPairs
		perm.PrefixListIds = j.PrefixListIds
		allSecGroupPerms = append(allSecGroupPerms, perm)
	}
	return
}

func enforceSecurityGroupPolicy(l []interface{}, session *session.Session,
	accountID string, planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing security policy")
	var outputErr policyItemOutputError
	if len(allEC2SecurityGroupsByAccount[planItem.Target.AccountID]) < 1 &&
		!noEC2SecurityGroupsByAccount[planItem.Target.AccountID] {
		err = loadEC2SecurityGroups(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr = processEC2Errors(l, err, planItem)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}
	}
	secGroups := allEC2SecurityGroupsByAccount[accountID]

	var validRuleCriterion = []string{"IngressProtocol", "IngressPort", "IngressIP"}
	var groupCriterion = []string{"GroupName", "HasAnyRules", "HasAnyIngressRules", "HasAnyEgressRules"}
	// TODO: Only allow Ingress filters OR egress filters, so check now or during plan?

	var anyFiltersMatch bool
SecGroup:
	for _, secGroup := range secGroups {
		var identifiers = []string{*secGroup.securityGroup.GroupId, *secGroup.securityGroup.GroupName}
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: identifiers,
			itemRegion:  secGroup.region,
		}) {
			continue
		}
		if !h.StringInSlice(secGroup.region, planItem.Target.Regions) {
			continue
		}
		var groupFiltersMatch bool
		// Combine ingress and ingress permissions to single sequence so we can loop once
		allSecGroupPerms, hasAnyRules, hasAnyIngressRules,
		hasAnyEgressRules := combineSecGroupPermissions(secGroup.securityGroup)
		// Process group specific filters, before going through rule based filters
		// If we don't match a group based filter on this sec group, then policy doesn't match, so we'll continue
		for _, f := range planItem.Policy.Filters {
			var groupFilterMatch bool
			// ignore rule based filters
			if !h.StringInSlice(f.Criterion, groupCriterion) {
				continue
			}
			switch f.Criterion {
			case "HasAnyRules":
				groupFilterMatch = filterHasAnyRules(f, hasAnyRules)
			case "HasAnyIngressRules":
				groupFilterMatch = filterHasAnyIngressRules(f, hasAnyIngressRules)
			case "HasAnyEgressRules":
				groupFilterMatch = filterHasAnyEgressRules(f, hasAnyEgressRules)
			case "GroupName":
				groupFilterMatch = filterGroupName(f, &secGroup)
			}
			if groupFilterMatch {
				groupFiltersMatch = true
			} else {
				// if any filter fails, then jump to next sec group
				groupFiltersMatch = false
				continue SecGroup
			}
		}
		if groupFiltersMatch {
			// if there are no rule based filters, then add now, other wise carry on...
			var ruleBasedFilters bool
			for _, cf := range planItem.Policy.Filters {
				if h.StringInSlice(cf.Criterion, validRuleCriterion) {
					ruleBasedFilters = true
					break
				}
			}
			if !ruleBasedFilters {
				anyFiltersMatch = true
				output = appendPolicyOutput(l, output, createPolicyOutputInput{
					PlanItem:     planItem,
					ResourceName: getNameTag(secGroup.securityGroup.Tags),
					ResourceArn: *secGroup.securityGroup.GroupId + " - " +
						*secGroup.securityGroup.GroupName + " (" + secGroup.region + ")",
					IssuesFound: true,
				})
			}

		}
		// Process rule specific filters
	LoopPermissions:
		for _, perm := range allSecGroupPerms {
			var filtersMatch bool
			for _, filter := range planItem.Policy.Filters {
				// Ignore group based filters
				if h.StringInSlice(filter.Criterion, groupCriterion) {
					continue
				}
				// check criterion is valid
				if !h.StringInSlice(filter.Criterion, validRuleCriterion) {
					err = errors.Errorf("criterion: \"%s\" is not implemented, "+
						"yet exists in catalogue. Oops", filter.Criterion)
					return
				}
				var filterMatch bool
				if filter.Criterion == "IngressProtocol" && perm.ingress {
					filterMatch, err = filterIngressProtocol(filter, perm)
				} else if filter.Criterion == "IngressPort" && perm.ingress {
					filterMatch, err = filterIngressPort(filter, perm)
				} else if filter.Criterion == "IngressIP" && perm.ingress {
					filterMatch, err = filterIP(filter, perm.IpRanges)
				} else if filter.Criterion == "EgressProtocol" && !perm.ingress {
					filterMatch, err = filterEgressProtocol(filter, perm)
				} else if filter.Criterion == "EgressPort" && !perm.ingress {
					filterMatch, err = filterEgressPort(filter, perm)
				} else if filter.Criterion == "EgressIP" && !perm.ingress {
					filterMatch, err = filterIP(filter, perm.IpRanges)
				}
				if err != nil {
					return
				}
				// If not found, then no point running more filters
				if !filterMatch {
					filtersMatch = false
					h.Debug(l, fmt.Sprintf("no filter match for: %s:%s\n",
						*secGroup.securityGroup.GroupName, *secGroup.securityGroup.GroupId))
					continue LoopPermissions
				} else {
					filtersMatch = true
				}
			}
			if filtersMatch {
				h.Debug(l, fmt.Sprintf("no filter match for: %s:%s\n",
					*secGroup.securityGroup.GroupName, *secGroup.securityGroup.GroupId))
				// We've got at least one set of matches
				anyFiltersMatch = true
				output = appendPolicyOutput(l, output, createPolicyOutputInput{
					PlanItem:     planItem,
					ResourceName: getNameTag(secGroup.securityGroup.Tags),
					ResourceArn: *secGroup.securityGroup.GroupId + " - " +
						*secGroup.securityGroup.GroupName + " (" + secGroup.region + ")",
					IssuesFound: true,
				})
			}
		}

	}
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}

	return
}

// group filters

func filterGroupName(filter r.Filter, secGroup *ec2SecurityGroup) (groupFilterMatch bool) {
	if (filter.Comparison == "==" && filter.Value == *secGroup.securityGroup.GroupName) ||
		(filter.Comparison == "!=" && filter.Value != *secGroup.securityGroup.GroupName) {
		groupFilterMatch = true
	}
	return
}

func filterHasAnyEgressRules(filter r.Filter, hasAnyEgressRules bool) (groupFilterMatch bool) {
	if (filter.Value == "true" && hasAnyEgressRules) || (filter.Value == "false" && !hasAnyEgressRules) {
		groupFilterMatch = true
	}
	return
}

func filterHasAnyIngressRules(filter r.Filter, hasAnyIngressRules bool) (groupFilterMatch bool) {
	if (filter.Value == "true" && hasAnyIngressRules) || (filter.Value == "false" && !hasAnyIngressRules) {
		groupFilterMatch = true
	}
	return
}

func filterHasAnyRules(filter r.Filter, hasAnyRules bool) (groupFilterMatch bool) {
	if (filter.Value == "true" && hasAnyRules) || (filter.Value == "false" && !hasAnyRules) {
		groupFilterMatch = true
	}
	return
}

// rule filters

func filterIngressProtocol(filter r.Filter, perm secGroupPerm) (filterMatch bool, err error) {
	if filter.Comparison == "allows" && (strings.ToLower(filter.Value) == *perm.IpProtocol || *perm.IpProtocol == "-1") {
		filterMatch = true
	}
	return
}

func filterEgressProtocol(filter r.Filter, perm secGroupPerm) (filterMatch bool, err error) {
	if filter.Comparison == "allows" && (strings.ToLower(filter.Value) == *perm.IpProtocol || *perm.IpProtocol == "-1") {
		filterMatch = true
	}
	return
}

func filterIngressPort(filter r.Filter, perm secGroupPerm) (filterMatch bool, err error) {
	var numVal int64
	numVal, err = h.ToInt64(filter.Value)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	if perm.FromPort != nil {
		if filter.Comparison == "allows" && h.NumBetween(numVal, *perm.FromPort, *perm.ToPort) {
			filterMatch = true
		}
	}
	return
}

func filterEgressPort(filter r.Filter, perm secGroupPerm) (filterMatch bool, err error) {
	var numVal int64
	numVal, err = h.ToInt64(filter.Value)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	if perm.FromPort != nil {
		if filter.Comparison == "allows" && h.NumBetween(numVal, *perm.FromPort, *perm.ToPort) {
			filterMatch = true
		}
	}
	return
}

func filterIP(filter r.Filter, ranges []*ec2.IpRange) (filterMatch bool, err error) {
	switch filter.Comparison {
	case "allows":
		var inIP net.IP
		inIP, _, err = net.ParseCIDR(filter.Value)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		for _, ipRange := range ranges {
			_, cidrIPRange, _ := net.ParseCIDR(*ipRange.CidrIp)
			if cidrIPRange.Contains(inIP) {
				filterMatch = true
				break
			}
		}
	}
	return
}

func enforceInstancePolicy(l []interface{}, session *session.Session,
	planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing instance policy")
	var outputErr policyItemOutputError
	if len(allEC2InstancesByAccount[planItem.Target.AccountID]) < 1 &&
		!noEC2InstancesByAccount[planItem.Target.AccountID] {
		err = loadEC2Instances(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr = processEC2Errors(l, err, planItem)
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:    planItem,
				IssuesFound: true,
				OutputErr:   outputErr,
			})
			logPolicyOutputItemError(l, outputErr)
			return
		}
	}

	// Loop through regions
	var filtersMatch, anyFiltersMatch bool
	var details []enforcePolicyOutputItemDetail
	for i := range allEC2InstancesByAccount[planItem.Target.AccountID] {
		instance := allEC2InstancesByAccount[planItem.Target.AccountID][i]
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{getNameTag(instance.instance.Tags), *instance.instance.InstanceId},
			itemRegion:  instance.region,
		}) {
			continue
		}
		for _, filter := range planItem.Policy.Filters {
			// imp:ec2:Instance:InstanceType
			if filter.Criterion == "InstanceType" {
				if filter.Comparison == "in" {
					if h.StringInSlice(*instance.instance.InstanceType, filter.Values) {
						filtersMatch = true
						// details = addEc2InstanceItemDetail(&details, instance)
					}
				} else if filter.Comparison == "not in" {
					if !h.StringInSlice(*instance.instance.InstanceType, filter.Values) {
						filtersMatch = true
						// details = addEc2InstanceItemDetail(&details, instance)
					}
				}
			}
		}
		if filtersMatch {
			// We've got at least one set of matches
			anyFiltersMatch = true
			output = appendPolicyOutput(l, output, createPolicyOutputInput{
				PlanItem:     planItem,
				Region:       instance.region,
				ResourceName: getNameTag(instance.instance.Tags),
				ResourceArn:  *instance.instance.InstanceId,
				Details:      details,
				IssuesFound:  true,
			})
		}

	}

	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}
