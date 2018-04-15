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
	"testing"

	"fmt"

	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
)

func TestMissingEmailProvider(t *testing.T) {
	email := r.Email{
		Source:  "rod@example.com",
		Subject: "test subject",
		Recipients: []string{
			"bob@example.com",
			"james@example.com"},
	}
	err := validateEmailSettings(email)
	if err.Error() != "email provider not specified" {
		t.Error("missing provider was not caught")
	}
}

func TestMissingEmailSource(t *testing.T) {
	email := r.Email{
		Provider: "smtp",
		Subject:  "test subject",
		Recipients: []string{
			"bob@example.com",
			"james@example.com"},
	}
	err := validateEmailSettings(email)
	if err.Error() != "email source not specified" {
		t.Error("missing email source was not caught")
	}
}

func TestValidateEmailProvider(t *testing.T) {
	email := r.Email{
		Provider: "invalid",
		Source:   "rod@example.com",
		Subject:  "test subject",
		Recipients: []string{
			"bob@example.com",
			"james@example.com"},
	}
	err := validateEmailSettings(email)
	if err.Error() != "email provider 'invalid' not supported" {
		t.Error("invalid provider was not caught")
	}
}

func TestValidateRecipientsEmailAddresses(t *testing.T) {
	email := r.Email{
		Provider: "smtp",
		Source:   "rod@example.com",
		Subject:  "test subject",
		Recipients: []string{
			"bob@example.com",
			"jamesexample.com"},
	}
	err := validateEmailSettings(email)
	if err.Error() != "invalid email address 'jamesexample.com'" {
		t.Error("invalid email address not caught")
	}

}

func TestValidateRecipientsSourceAddress(t *testing.T) {
	email := r.Email{
		Provider: "smtp",
		Source:   "Rod <rodexample.com>",
		Subject:  "test subject",
		Recipients: []string{
			"bob@example.com",
			"james@example.com"},
	}
	err := validateEmailSettings(email)
	if err.Error() != "invalid email address 'rodexample.com'" {
		t.Error("invalid email address not caught")
	}

}

func TestValidatePolicyFilters(t *testing.T) {
	criterionOne := h.Criterion{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	}
	criteriaOne := []h.Criterion{criterionOne}
	resourceOne := h.Resource{Name: "PasswordLastUsed", Criteria: criteriaOne}
	filterOne := r.Filter{Comparison: "<", Criterion: "PasswordLastUsed", Unit: "days", Value: "30"}
	errOne := validatePolicyFilters("PasswordLastUsed", resourceOne, filterOne)
	if errOne != nil {
		t.Error("valid policy filter marked invalid")
	}

	criterionTwo := h.Criterion{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	}
	criteriaTwo := []h.Criterion{criterionTwo}
	resourceTwo := h.Resource{Name: "PasswordLastUsed", Criteria: criteriaTwo}
	filterTwo := r.Filter{Comparison: "<", Criterion: "PasswordLastUsed", Unit: "milllenia", Value: "30"}
	errTwo := validatePolicyFilters("PasswordLastUsed", resourceTwo, filterTwo)
	if errTwo.Error() != fmt.Sprintf("illegal unit '%s' in filter for resource: %s", filterTwo.Unit, resourceTwo.Name) {
		t.Error("illegal filter unit returned wrong error message")
	}

	criterionThree := h.Criterion{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	}
	criteriaThree := []h.Criterion{criterionThree}
	resourceThree := h.Resource{Name: "PasswordLastUsed", Criteria: criteriaThree}
	filterThree := r.Filter{Comparison: "in", Criterion: "PasswordLastUsed", Unit: "days", Value: "30"}
	errThree := validatePolicyFilters("PasswordLastUsed", resourceThree, filterThree)
	expectedErrThree := fmt.Sprintf(
		"illegal comparison operator '%s' in filter for unit '%s' on resource %s",
		filterThree.Comparison, filterThree.Unit, resourceThree.Name)
	if errThree.Error() != expectedErrThree {
		t.Error("illegal comparison operator returned wrong error message")
	}

	criterionFour := h.Criterion{
		Name:        "PasswordLastUsed",
		Comparisons: []string{"<", ">"},
		Units:       []string{"days", "hours", "minutes", "seconds"},
	}
	criteriaFour := []h.Criterion{criterionFour}
	resourceFour := h.Resource{Name: "PasswordLastUsed", Criteria: criteriaFour}
	filterFour := r.Filter{Comparison: "in", Criterion: "Invalid", Unit: "days", Value: "30"}
	errFour := validatePolicyFilters("PasswordLastUsed", resourceFour, filterFour)
	expectedErrFour := fmt.Sprintf(
		"illegal criterion '%s' in filter for resource: %s", filterFour.Criterion, resourceFour.Name)
	if errFour.Error() != expectedErrFour {
		t.Error("illegal criterion returned wrong error message")
		t.Error(expectedErrFour)
		t.Error(errFour.Error())

	}
}
