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
	"bufio"
	"os"

	"fmt"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/pkg/errors"
	"github.com/segmentio/ksuid"
	"gopkg.in/yaml.v2"
)

const (
	defaultAccountsPath = "accounts.yml"
)

type plan []PlanItem

type planItemTarget struct {
	AccountID    string
	AccountAlias string
	Regions      []string
	Role         string
	ExternalID   string `yaml:"ExternalId"`
}

type ignoredResource struct {
	AccountID string
	Region    string
	Service   string
	Resource  string
	ID        string
}

type PlanItem struct {
	ID               string
	Target           planItemTarget
	Policy           r.Policy
	ignoredResources []ignoredResource
	Play             *r.Play
}

type CreatePlanInput struct {
	Playbook   r.Playbook
	Accounts   []r.Account
	Policies   r.Policies
	Args       r.CommandLineArgs
	AssueRole  string
	OutputFile string
}

type CreatePlanOutput struct {
	Plan  *plan
	Email r.Email
	Slack r.Slack
}

var globalServices = []string{"iam", "cloudfront"}

func getAllRegionsForService(service string) (result []string) {
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	var resMaps []map[string]endpoints.Region
	for _, p := range partitions {
		resMap, _ := endpoints.RegionsForService(endpoints.DefaultPartitions(), p.ID(), service)
		resMaps = append(resMaps, resMap)
	}
	keys := make([]string, 0, len(resMaps))
	for _, resMap := range resMaps {
		for _, ra := range resMap {
			if !h.StringInSlice(ra.ID(), badRegions[service]) {
				keys = append(keys, ra.ID())
			}
		}
	}
	result = keys
	return
}

func isServiceImplementedInRegion(service, region string) (result string) {
	result = "no"
	if h.StringInSlice(service, globalServices) {
		result = "global"
		return
	}

	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	var resMaps []map[string]endpoints.Region
	for _, p := range partitions {
		resMap, _ := endpoints.RegionsForService(endpoints.DefaultPartitions(), p.ID(), service)
		resMaps = append(resMaps, resMap)
	}
	for _, resMap := range resMaps {
		for _, ra := range resMap {
			if ra.ID() == region {
				result = "yes"
				break
			}
		}
	}

	return
}

func getPlaybookTargetsMatchingRole(account r.Account,
	playBookTarget r.PlaybookTarget) (targets []planItemTarget, err error) {
	var targetRole string
	var targetExternalID string
	for _, role := range account.Roles {
		if role.RoleType == playBookTarget.RoleType {
			targetRole = role.Name
			targetExternalID = role.ExternalID
			break
		}
	}
	targets = append(targets, planItemTarget{AccountAlias: account.Alias, AccountID: account.ID,
		Role: targetRole, ExternalID: targetExternalID})
	return
}

func getPlayTargets(accounts []r.Account, playBookTargets []r.PlaybookTarget) (targets []planItemTarget, err error) {
	for _, acc := range accounts {
		for _, playBookTarget := range playBookTargets {
			if len(playBookTarget.Include) > 0 {
				if !h.StringInSlice(acc.Alias, playBookTarget.Include) && !h.StringInSlice(acc.ID, playBookTarget.Include) {
					continue
				}
			}
			if len(playBookTarget.Exclude) > 0 { // Skip accounts that match provided exclude list
				if h.StringInSlice(acc.Alias, playBookTarget.Exclude) || h.StringInSlice(acc.ID, playBookTarget.Exclude) {
					continue
				}
			}
			result, getErr := getPlaybookTargetsMatchingRole(acc, playBookTarget)
			if getErr == nil {
				targets = append(targets, result...)
			}
		}
	}
	return
}

type LoadConfigsInput struct {
	PlaybookFilePath string
	PoliciesFilePath string
	AccountsFilePath string
	Args             r.CommandLineArgs
}

func processignoredResources(input []string) (output []ignoredResource, err error) {
	for _, ir := range input {
		var accID, region, service, resource, resourceID string
		accID, region, service, resource, resourceID, err = h.GetignoredResourceParts(ir)
		if err != nil {
			return
		}
		output = append(output, ignoredResource{
			AccountID: accID,
			Region:    region,
			Service:   service,
			Resource:  resource,
			ID:        resourceID,
		})
	}
	return
}

func CreatePlan(loggers []interface{}, input *CreatePlanInput) (output CreatePlanOutput, err error) {
	h.Notice(loggers, "creating plan")

	output.Email = input.Playbook.Email
	output.Slack = input.Playbook.Slack

	if emailConfigDefined(output.Email) {
		err = validateEmailSettings(output.Email)
		if err != nil {
			return
		}
	}
	if slackConfigDefined(output.Slack) {
		err = validateSlackSettings(output.Slack)
		if err != nil {
			return
		}
	}

	var planList plan
	var singleTarget bool
	// If no accounts have been specified, then we'll assume it's a single AWS account
	if len(input.Playbook.AccountsFile) == 0 {
		singleTarget = true
	}

	defaultTargets := input.Playbook.Targets
	for _, play := range input.Playbook.Plays {
		var itemPolicies []r.Policy
		for _, playPolicy := range play.Policies {
			policy, getPolicyByNameErr := getPolicyByName(playPolicy, input.Policies)
			if getPolicyByNameErr != nil {
				err = getPolicyByNameErr
				return
			}
			itemPolicies = append(itemPolicies, policy)
		}

		var playRegionsSpecified = false
		if len(play.Regions) > 0 {
			playRegionsSpecified = true
		}
		var processedItemPolicies PlanItem

		if !singleTarget {
			var targetsInput []r.PlaybookTarget
			if len(play.Targets) > 0 {
				targetsInput = play.Targets
			} else if len(defaultTargets) > 0 {
				targetsInput = defaultTargets
			} else {
				err = errors.Wrap(err, "no targets could be found")
			}

			// create a map of account id to aliases to validate targets against
			accIDToAlias := make(map[string]string)
			accAliasToID := make(map[string]string)
			for _, acc := range input.Accounts {
				accIDToAlias[acc.ID] = acc.Alias
				accAliasToID[acc.Alias] = acc.ID
			}
			// Check include and exclude targets are valid
			for _, target := range targetsInput {
				for _, accToInclude := range target.Include {
					if _, aliasPresent := accAliasToID[accToInclude]; !aliasPresent {
						if _, idPresent := accIDToAlias[accToInclude]; !idPresent {
							err = fmt.Errorf("account to include: '%s' does not exist in accounts file", accToInclude)
							err = errors.WithStack(err)
							return
						}
					}
				}
			}

			targets, getPlayTargetsErr := getPlayTargets(input.Accounts, targetsInput)
			if getPlayTargetsErr != nil {
				err = getPlayTargetsErr
				return
			}
			for _, target := range targets {
				for _, itemPolicy := range itemPolicies {
					processedItemPolicies, err = processItemPolicy(itemPolicy, playRegionsSpecified, play, target, input.Args)
					planList = append(planList, processedItemPolicies)
				}

			}
		} else {
			for _, itemPolicy := range itemPolicies {
				processedItemPolicies, err = processItemPolicy(itemPolicy, playRegionsSpecified, play, planItemTarget{}, input.Args)
				planList = append(planList, processedItemPolicies)
			}
		}

	}

	d, err := yaml.Marshal(&planList)
	if err != nil {
		return
	}
	output.Plan = &planList
	if input.OutputFile != "" {
		var f *os.File
		f, err = os.Create(input.OutputFile)
		if err != nil {
			return
		}
		defer func(f *os.File) {
			err = f.Close()
			if err != nil {
				return
			}
		}(f)

		w := bufio.NewWriter(f)
		_, err = w.Write(d)
		if err != nil {
			return
		}
		err = w.Flush()
		if err != nil {
			return
		}
		defer func(f *os.File) {
			err = f.Close()
			if err != nil {
				return
			}
		}(f)
	}
	return
}

func processItemPolicy(itemPolicy r.Policy, playRegionsSpecified bool, play r.Play,
	target planItemTarget, args r.CommandLineArgs) (planItem PlanItem, err error) {
	// If Regions specified, build a list of regions it should be run against, based on whether or not
	// the service exists in the specified regions
	// If regions specified and service doesn't exist in one or more, give warning but continue
	var validTargetRegions []string
	if playRegionsSpecified {
		for _, specifiedRegion := range play.Regions {
			// TODO: Generate a map up front rather than call every time
			service, _, _ := h.GetResourceParts(itemPolicy.Resource)
			isImplemented := isServiceImplementedInRegion(service, specifiedRegion)
			// If service is implemented for this region (but not global), then set as valid
			if isImplemented == "yes" {
				validTargetRegions = append(validTargetRegions, specifiedRegion)
			}
			// If service is implemented for global, then set to global and return
			if isImplemented == "global" {
				validTargetRegions = append(validTargetRegions, "global")
			}
		}
	} else {
		service, _, _ := h.GetResourceParts(itemPolicy.Resource)
		validTargetRegions = getAllRegionsForService(service)
	}

	// if regions were specified on the command line, then reduce valid regions to those
	var finalRegions []string
	if len(args.Regions) > 0 {
		for _, region := range validTargetRegions {
			if h.StringInSlice(region, args.Regions) {
				finalRegions = append(finalRegions, region)
			}
		}
	} else {
		finalRegions = validTargetRegions
	}

	id := ksuid.New()
	target.Regions = finalRegions
	var ignoredResources []ignoredResource
	if len(play.IgnoreResources) > 0 {
		ignoredResources, err = processignoredResources(play.IgnoreResources)
		if err != nil {
			return
		}
	}

	planItem = PlanItem{ID: id.String(),
		Target: target, Policy: itemPolicy, Play: &play, ignoredResources: ignoredResources}
	return
}
