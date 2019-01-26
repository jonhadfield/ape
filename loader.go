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
	"io/ioutil"
	"os"
	"strings"

	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/pkg/errors"
	lev "github.com/texttheater/golang-levenshtein/levenshtein"
	yaml "gopkg.in/yaml.v2"
)

func loadPolicies(policiesFilePath string) (policies r.Policies, err error) {
	policyFileContent, readErr := ioutil.ReadFile(policiesFilePath)
	if readErr != nil {
		return policies, readErr
	}
	policies, err = ParsePoliciesFileContent(policyFileContent)
	return
}

func ParsePoliciesFileContent(content []byte) (policies r.Policies, err error) {
	unmarshalErr := yaml.Unmarshal(content, &policies)
	if unmarshalErr != nil {
		return policies, unmarshalErr
	}
	updatedPolicies := make([]r.Policy, 0, len(policies.Policies))
	var modified bool
	// set policy default to medium
	for i := range policies.Policies {
		policy := policies.Policies[i]
		policy.Name = strings.TrimSpace(policy.Name)
		if policy.Severity == "" {
			modified = true
			policy.Severity = "medium"
		}
		if len(policy.Actions) == 0 {
			modified = true
			policy.Actions = append(policy.Actions, "report")
		}
		updatedPolicies = append(updatedPolicies, policy)
	}
	if modified {
		policies.Policies = updatedPolicies
	}

	err = validatePolicies(policies)
	return
}

func loadPlaybook(playbookFilePath string) (playbook r.Playbook, err error) {
	var playbookFileContent []byte
	playbookFileContent, err = ioutil.ReadFile(playbookFilePath)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	playbook, err = ParsePlaybookFileContent(playbookFileContent)
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func ParsePlaybookFileContent(content []byte) (playbook r.Playbook, err error) {
	unmarshalErr := yaml.Unmarshal(content, &playbook)
	if unmarshalErr != nil {
		err = errors.WithStack(unmarshalErr)
		return
	}
	return
}

func loadAccounts(accountsFilePath string) (accounts []r.Account, err error) {
	accounts, err = readAccounts(accountsFilePath)
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func checkAccountsFilePath(l []interface{},
	playbook r.Playbook, input LoadConfigsInput) (accountsFilePath string, err error) {
	if input.AccountsFilePath != "" {
		// check path specified on command line points to an available file
		if _, err = os.Stat(input.AccountsFilePath); os.IsNotExist(err) {
			err = errors.Errorf("accounts file specified as command line argument '%s' does not exist", input.AccountsFilePath)
		} else {
			accountsFilePath = input.AccountsFilePath
		}
	} else if playbook.AccountsFile != "" {
		if _, err = os.Stat(playbook.AccountsFile); os.IsNotExist(err) {
			h.Info(l, fmt.Sprintf("accounts file specified in playbook '%s' does not exist", playbook.AccountsFile))
		} else {
			h.Debug(l, fmt.Sprintf("using accounts file specified in playbook '%s'", playbook.AccountsFile))
			accountsFilePath = playbook.AccountsFile
		}
	} else if _, err = os.Stat("accounts.yml"); err == nil {
		// path not specified, so trying default
		accountsFilePath = "accounts.yml"
	} else {
		h.Notice(l, "accounts file not specified on command line nor found in playbook - going to assume single account")
	}
	return
}

func checkPoliciesFilePath(l []interface{},
	playbook r.Playbook, input LoadConfigsInput) (policiesFilePath string, err error) {
	var defaultPoliciesFilePath = "policies.yml"
	h.Debug(l, "checking policies filepath")
	if input.PoliciesFilePath != "" {
		// check path specified on command line points to an available file
		if _, err = os.Stat(input.PoliciesFilePath); os.IsNotExist(err) {
			h.Error(l, fmt.Sprintf("failed to load policies file specified on the command line: '%s'", input.PoliciesFilePath))
			err = errors.Errorf("policies file specified on command line: '%s' does not exist", input.PoliciesFilePath)
			h.OutputError(err)
			os.Exit(1)
		} else {
			// specified path points to a file that exists
			policiesFilePath = input.PoliciesFilePath
		}
	} else if playbook.PoliciesFile != "" {
		h.Debug(l, fmt.Sprintf("trying to load policies file from playbook: '%s'", playbook.PoliciesFile))
		if _, err = os.Stat(playbook.PoliciesFile); os.IsNotExist(err) {
			err = errors.Errorf("policies file specified in playbook '%s' does not exist", playbook.PoliciesFile)
			return
		}
		h.Debug(l, fmt.Sprintf("using policies file specified in playbook: '%s'", playbook.PoliciesFile))
		policiesFilePath = playbook.PoliciesFile
	} else {
		// path not specified, so trying default
		if _, err = os.Stat(defaultPoliciesFilePath); err == nil {
			// default path points to a file that exists
			policiesFilePath = defaultPoliciesFilePath
		}
	}
	return
}

func playbookHasTargets(playbook *r.Playbook) (result bool) {
	if len(playbook.Targets) > 0 {
		result = true
	} else {
		for _, play := range playbook.Plays {
			if len(play.Targets) > 0 {
				result = true
				break
			}
		}
	}
	return
}

func LoadConfigs(l []interface{}, input LoadConfigsInput) (configs r.Configs, err error) {
	h.Debug(l, "loading configs")
	configs.Playbook, err = loadPlaybook(input.PlaybookFilePath)
	if err != nil {
		return
	}

	// only read accounts if playbook specifies any targets
	if playbookHasTargets(&configs.Playbook) {
		var accountsFilePath string
		accountsFilePath, err = checkAccountsFilePath(l, configs.Playbook, input)
		if err != nil {
			h.Info(l, "accounts file")
			return
		}
		if accountsFilePath != "" {
			configs.Accounts, err = loadAccounts(accountsFilePath)
			if err != nil {
				return
			}
		}
	}

	var policiesFilePath string
	policiesFilePath, err = checkPoliciesFilePath(l, configs.Playbook, input)
	if err != nil {
		return
	}
	configs.Policies, err = loadPolicies(policiesFilePath)
	if err != nil {
		return
	}
	return
}

func getPolicyNameSuggestion(policyName string, policies r.Policies) (suggestion string) {
	suggestionThreshold := 15
	type bestMatch struct {
		name string
		dist int
	}
	var dist int
	var best bestMatch
	for i := range policies.Policies {
		policy := policies.Policies[i]
		dist = lev.DistanceForStrings([]rune(policyName), []rune(policy.Name), lev.DefaultOptions)
		if best == (bestMatch{}) || dist < best.dist {
			best.name = policy.Name
			best.dist = dist
		}
	}
	if best.dist <= suggestionThreshold {
		suggestion = best.name
	}
	return
}

func getPolicyByName(policyName string, policies r.Policies) (policy r.Policy, err error) {
	for i := range policies.Policies {
		existingPolicy := policies.Policies[i]
		if existingPolicy.Name == policyName {
			return existingPolicy, nil
		}
	}
	// check if there's another close match we could suggest
	suggestion := getPolicyNameSuggestion(policyName, policies)
	if suggestion != "" {
		err = errors.Errorf("policy: '%s' not found\ndid you mean: '%s'?", policyName, suggestion)
	} else {
		err = errors.Errorf("policy: '%s' not found", policyName)
	}
	return
}

func readAccounts(accountsPath ...string) (ret []r.Account, err error) {
	var path string

	if len(accountsPath) == 1 && accountsPath[0] != "" {
		path = accountsPath[0]
	} else {
		path = defaultAccountsPath
	}
	if _, err = os.Stat(path); err == nil {
		_, openErr := os.Open(path)
		if openErr != nil {
			err = errors.WithStack(openErr)
			return
		}
		accountsFileContent, readErr := ioutil.ReadFile(path)
		if readErr != nil {
			err = errors.WithStack(readErr)
			return
		}
		ret, err = parseAccountsFileContent(accountsFileContent)
	}

	return
}

func parseAccountsFileContent(content []byte) (accounts []r.Account, err error) {
	var accountsInstance r.Accounts
	unmarshalErr := yaml.Unmarshal(content, &accountsInstance)
	if unmarshalErr != nil {
		err = errors.WithStack(unmarshalErr)
		return
	}
	accounts = accountsInstance.Accounts
	return
}
