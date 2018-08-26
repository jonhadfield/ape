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

	"sync"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	h "github.com/jonhadfield/ape/helpers"
	"github.com/pkg/errors"
)

type vpc struct {
	region string
	vpc    ec2.Vpc
}
type vpcFlowLog struct {
	region  string
	flowLog ec2.FlowLog
}

var allVpcsByAccount map[string][]vpc
var allVpcsByAccountMutex sync.Mutex
var noVpcsByAccount map[string]bool
var allFlowLogsByAccount map[string][]vpcFlowLog
var allFlowLogsByAccountMutex sync.Mutex
var noFlowLogsByAccount map[string]bool

func describeVpcs(svc ec2iface.EC2API) (vpcs []*ec2.Vpc, err error) {
	var output *ec2.DescribeVpcsOutput
	output, err = svc.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	vpcs = append(vpcs, output.Vpcs...)
	return
}

func describeFlowLogs(svc ec2iface.EC2API) (flowLogs []*ec2.FlowLog, err error) {
	var output *ec2.DescribeFlowLogsOutput
	output, err = svc.DescribeFlowLogs(&ec2.DescribeFlowLogsInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	flowLogs = append(flowLogs, output.FlowLogs...)
	return
}

func loadVpcData(l []interface{}, session *session.Session, accountID string, regions []string) (err error) {
	if allVpcsByAccount == nil {
		allVpcsByAccount = make(map[string][]vpc)
	}
	if noVpcsByAccount == nil {
		noVpcsByAccount = make(map[string]bool)
	}

	if allFlowLogsByAccount == nil {
		allFlowLogsByAccount = make(map[string][]vpcFlowLog)
	}
	if noFlowLogsByAccount == nil {
		noFlowLogsByAccount = make(map[string]bool)
	}

	numRegions := len(regions)
	var ch = make(chan error)
	for _, region := range regions {
		svc := getEC2Client(session, accountID, region)
		go func(region string) {
			var routineErr error
			h.Debug(l, fmt.Sprintf("loading vpc data for region: %s\n", region))
			var vpcs []*ec2.Vpc
			var flowLogs []*ec2.FlowLog

			// load vpcs
			vpcs, routineErr = describeVpcs(svc)
			if routineErr != nil {
				routineErr = errors.WithStack(routineErr)
				ch <- routineErr
			}

			// load flow logs
			flowLogs, routineErr = describeFlowLogs(svc)
			if routineErr != nil {
				ch <- routineErr
			}
			for _, vpcItem := range vpcs {
				allVpcsByAccountMutex.Lock()
				allVpcsByAccount[accountID] = append(allVpcsByAccount[accountID], vpc{
					region: region,
					vpc:    *vpcItem,
				})
				allVpcsByAccountMutex.Unlock()
			}

			for _, flowLog := range flowLogs {
				allFlowLogsByAccountMutex.Lock()
				allFlowLogsByAccount[accountID] = append(allFlowLogsByAccount[accountID], vpcFlowLog{
					region:  region,
					flowLog: *flowLog,
				})
				allFlowLogsByAccountMutex.Unlock()
			}
			ch <- routineErr
		}(region)
	}

	for i := 1; i <= numRegions; i++ {
		output := <-ch
		if output != nil {
			err = errors.WithStack(output)
			return
		}
	}
	if len(allVpcsByAccount[accountID]) == 0 {
		noVpcsByAccount[accountID] = true
	}
	if len(allFlowLogsByAccount[accountID]) == 0 {
		noFlowLogsByAccount[accountID] = true
	}
	return
}

func enforceVpcPolicy(l []interface{}, session *session.Session, planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing vpc policy")
	if len(allVpcsByAccount[planItem.Target.AccountID]) < 1 && !noVpcsByAccount[planItem.Target.AccountID] {
		err = loadVpcData(l, session, planItem.Target.AccountID, planItem.Target.Regions)
		if err != nil {
			outputErr := processEC2Errors(l, err, planItem)
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
	for i := range allVpcsByAccount[planItem.Target.AccountID] {
		vpcItem := allVpcsByAccount[planItem.Target.AccountID][i]
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*vpcItem.vpc.VpcId, getNameTag(vpcItem.vpc.Tags)},
		}) {
			continue
		}
		var filterMatch, filtersMatch bool
		var message string
		if h.StringInSlice(vpcItem.region, planItem.Target.Regions) {
			for _, filter := range planItem.Policy.Filters {
				switch filter.Criterion {
				case "HasEnabledFlowLog":
					// vpc:Vpc:HasEnabledFlowLog
					var vpcHasEnabledFlowLog bool
					for _, flowLog := range allFlowLogsByAccount[planItem.Target.AccountID] {
						if *flowLog.flowLog.ResourceId == *vpcItem.vpc.VpcId {
							vpcHasEnabledFlowLog = true
						}
					}
					if vpcHasEnabledFlowLog && filter.Value == "true" {
						filterMatch = true
					} else if !vpcHasEnabledFlowLog && filter.Value == "false" {
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
							Region:       vpcItem.region,
							Message:      message,
							ResourceName: getNameTag(vpcItem.vpc.Tags),
							ResourceArn:  *vpcItem.vpc.VpcId,
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
