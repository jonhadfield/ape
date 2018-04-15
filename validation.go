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

	r "github.com/jonhadfield/ape/root"

	"reflect"

	"strings"

	h "github.com/jonhadfield/ape/helpers"

	"regexp"

	"github.com/pkg/errors"
)

func validatePolicyFilters(policyResource string, resource h.Resource, filter r.Filter) (err error) {
	var validCriterion bool
	for _, cri := range resource.Criteria {
		// Check name
		if strings.ToLower(filter.Criterion) == strings.ToLower(cri.Name) {
			validCriterion = true
			// Check units
			if strings.ToLower(filter.Unit) != "" && !h.StringInSlice(filter.Unit, h.StringSliceToLower(cri.Units)) {
				err = fmt.Errorf("illegal unit '%s' in filter for resource: %s", filter.Unit, resource.Name)
				return
			}
			// Check comparisons
			if strings.ToLower(filter.Comparison) != "" && !h.StringInSlice(filter.Comparison, h.StringSliceToLower(cri.Comparisons)) {
				err = fmt.Errorf("illegal comparison operator '%s' in filter for unit '%s' on resource %s",
					filter.Comparison, filter.Unit, policyResource)
				return
			}
		}
	}
	if !validCriterion {
		err = errors.Errorf("illegal criterion '%s' in filter for resource: %s", filter.Criterion, resource.Name)
	}
	return
}

func validatePolicyResourceAndFilters(policy r.Policy) (err error) {
	service, resource, _ := h.GetResourceParts(policy.Resource)
	for _, impService := range h.ImplementedServices {
		if service == impService.Name {
			for _, impResource := range impService.Resources {
				if resource == impResource.Name {
					// Check filters
					for _, filter := range policy.Filters {
						err = validatePolicyFilters(policy.Resource, impResource, filter)
						if err != nil {
							return
						}
					}
				}
			}
		}
	}
	return
}

func validatePolicies(policies r.Policies) (err error) {
	for _, policy := range policies.Policies {
		// Check specified resource is implemented
		err = validatePolicyResourceAndFilters(policy)
		if err != nil {
			return
		}
		// Check severity (if specified) is valid
		if _, okSec := severities[policy.Severity]; !okSec {
			err = fmt.Errorf("invalid severity: '%s' for policy: '%s'", policy.Severity, policy.Name)
			return
		}

	}
	return
}

func emailConfigDefined(email r.Email) (result bool) {
	if !reflect.DeepEqual(email, r.Email{}) {
		result = true
	}
	return
}

func slackConfigDefined(config r.Slack) (result bool) {
	if !reflect.DeepEqual(config, r.Slack{}) {
		result = true
	}
	return
}

func extractEmail(input string) (output string) {
	if strings.Contains(input, "<") {
		output = h.GetStringInBetween(input, "<", ">")
	} else {
		output = input
	}
	return
}

func validateEmailSettings(email r.Email) (err error) {
	supportedProviders := []string{"ses", "smtp"}
	if emailConfigDefined(email) {
		if email.Provider == "" {
			err = fmt.Errorf("email provider not specified")
			return
		}

		// TODO: Check minimum configuration (to, from, etc.)
		if email.Source == "" {
			err = fmt.Errorf("email source not specified")
			return
		}

		if !h.StringInSlice(email.Provider, supportedProviders) {
			err = fmt.Errorf("email provider '%s' not supported", email.Provider)
			return
		}
		emailRegexp := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
		// validate recipient email addresses
		for _, emailAddr := range email.Recipients {
			if !emailRegexp.MatchString(extractEmail(emailAddr)) {
				err = fmt.Errorf("invalid email address '%s'", extractEmail(emailAddr))
				return
			}
		}
		// validate source email address
		if !emailRegexp.MatchString(extractEmail(email.Source)) {
			err = fmt.Errorf("invalid email address '%s'", extractEmail(email.Source))
			return
		}

		// TODO: Check provider specific configuration
	}
	return
}

func validateSlackSettings(config r.Slack) (err error) {
	if slackConfigDefined(config) {
		var missingItems []string
		var missingItemsOutput string
		if config.Channel == "" {
			missingItems = append(missingItems, "channel")
		}
		if config.Token == "" {
			missingItems = append(missingItems, "token")
		}
		if config.Username == "" {
			missingItems = append(missingItems, "username")
		}
		if len(missingItems) > 0 {
			missingItemsOutput = strings.Join(missingItems, ",")
			err = fmt.Errorf("slack configuration missing items: '%s'", missingItemsOutput)
		}
	}
	return
}
