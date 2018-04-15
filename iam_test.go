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

	"time"

	. "github.com/jonhadfield/ape/mocks"

	syslog "github.com/RackSec/srslog"
	h "github.com/jonhadfield/ape/helpers"
	"github.com/jonhadfield/ape/root"
	. "github.com/smartystreets/goconvey/convey"

	"fmt"

	"github.com/aws/aws-sdk-go/service/iam"
)

func TestFilterHasMFADevice(t *testing.T) {
	mockSvc := &MockIAMClient{}
	filterHas := root.Filter{
		Criterion: "HasMFADevice",
		Value:     "true",
	}
	var userWith iamUser
	userWith.UserName = h.PtrToStr("Jon")
	resultWith, errWith := filterHasMFADevice(mockSvc, userWith, &filterHas)
	if errWith != nil {
		t.Errorf("function returned error: %s", errWith.Error())
	}
	if !resultWith {
		t.Error("function incorrectly reports user doesn't have MFA")
	}

	mockSvc2 := &MockIAMClient2{}

	filterHasNot := root.Filter{
		Criterion: "HasMFADevice",
		Value:     "false",
	}
	var userWithout iamUser
	userWithout.UserName = h.PtrToStr("Jon")
	resultWithout, errWithout := filterHasMFADevice(mockSvc2, userWithout, &filterHasNot)
	if errWithout != nil {
		t.Errorf("function returned error: %s", errWithout.Error())
	}
	if !resultWithout {
		t.Error("function incorrectly reports user does have MFA")
	}

}

func TestFilterHasPassword(t *testing.T) {
	mockSvc := &MockIAMClient{}
	filter := root.Filter{
		Criterion: "HasPassword",
		Value:     "true",
	}
	var user iamUser
	user.UserName = h.PtrToStr("Jon")
	result, err := filterHasPassword(mockSvc, user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports user doesn't have password")
	}
}

func TestFilterPasswordLastUsed(t *testing.T) {
	filter := root.Filter{
		Criterion:  "PasswordLastUsed",
		Comparison: "<",
		Unit:       "days",
		Value:      "10",
	}
	now := time.Now().UTC()
	var user iamUser
	user.UserName = h.PtrToStr("Jon")
	user.PasswordLastUsed = &now
	result, err := filterPasswordLastUsed(user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports password last used not within valid time")
	}
}

func TestFilterAccessKeysLastUsed(t *testing.T) {
	mockSvc := &MockIAMClient{}
	filter := root.Filter{
		Criterion:  "AccessKeyLastUsed",
		Comparison: "<",
		Unit:       "days",
		Value:      "90",
	}
	now := time.Now().UTC()
	var userOne iamUser
	userOne.UserName = h.PtrToStr("root")
	userOne.PasswordLastUsed = &now
	userOne.CreateDate = &now
	userOne.UserId = h.PtrToStr("userid")
	userOne.Path = h.PtrToStr("path")
	userOne.Arn = h.PtrToStr("arn")
	userOne.CRAccessKey1LastUsedDate = now
	userOne.CRAccessKey1Active = false
	userOne.CRAccessKey2LastUsedDate = now
	userOne.CRAccessKey2Active = true
	inputOne := filterActiveAccessKeysLastUsedInput{
		svc:    mockSvc,
		user:   userOne,
		filter: &filter,
	}
	resultOne, errOne := filterActiveAccessKeysLastUsed(&inputOne)
	if errOne != nil {
		t.Errorf("function returned error: %s", errOne.Error())
	}
	if !resultOne {
		t.Error("function reports access key last used not within valid time")
	}
	var userTwo iamUser
	userTwo.UserName = h.PtrToStr("Jon")
	userTwo.PasswordLastUsed = &now
	userTwo.CreateDate = &now
	userTwo.UserId = h.PtrToStr("userid")
	userTwo.Path = h.PtrToStr("path")
	userTwo.Arn = h.PtrToStr("arn")

	inputTwo := filterActiveAccessKeysLastUsedInput{
		svc:    mockSvc,
		user:   userTwo,
		filter: &filter,
	}
	resultTwo, errTwo := filterActiveAccessKeysLastUsed(&inputTwo)
	if errTwo != nil {
		t.Errorf("function returned error: %s", errTwo.Error())
	}
	if !resultTwo {
		t.Error("function reports access key last used not within valid time")
	}
}

func TestFilterActiveAccessKeysAge(t *testing.T) {
	mockSvc := &MockIAMClient{}
	filter := root.Filter{
		Criterion:  "ActiveAccessKeysAge",
		Comparison: "<",
		Unit:       "days",
		Value:      "90",
	}
	now := time.Now().UTC()
	var user iamUser
	user.UserName = h.PtrToStr("Jon")
	user.PasswordLastUsed = &now
	user.CreateDate = &now
	user.UserId = h.PtrToStr("userid")
	user.Path = h.PtrToStr("path")
	user.Arn = h.PtrToStr("arn")

	result, err := filterActiveAccessKeysAge(mockSvc, user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports active access key age didn't return mocked response")
	}
}

func TestFilterUserName(t *testing.T) {
	var user iamUser
	user.UserName = h.PtrToStr("testUserName")

	filterOne := root.Filter{
		Criterion:  "UserName",
		Comparison: "in",
		Values:     []string{"userNameOne", "userNameTwo", "testUserName"},
	}
	filterTwo := root.Filter{
		Criterion:  "UserName",
		Comparison: "not in",
		Values:     []string{"userNameOne", "userNameTwo", "userNameThree"},
	}
	goodMatch := filterUserName(user, &filterOne)
	if !goodMatch {
		t.Error("match on existing username 'in' list returned false")
	}
	noMatch := filterUserName(user, &filterTwo)
	if !noMatch {
		t.Error("match on missing username 'not in' list returned true")
	}

}

func TestFilterHasManagedPolicyAttached(t *testing.T) {
	t.Parallel()
	Convey("Given a filter looking for a role with a specific managed policy attached", t, func() {
		var f = root.Filter{
			Criterion:  "HasManagedPolicyAttached",
			Comparison: "in",
			Values:     []string{"arn:aws:iam::aws:policy/AWSSupportAcces"},
		}
		Convey("When the managed policy exists", func() {
			mockSvc := &MockIAMClient{}
			result, _ := filterHasManagedPolicyAttached(mockSvc, iam.Role{}, &f)
			Convey("the result should be true", func() {
				So(result, ShouldBeTrue)
			})
		})
	})

	//var user User
	//user.UserName = h.PtrToStr("testUserName")
	//
	//filterOne := root.Filter{
	//	Criterion:  "UserName",
	//	Comparison: "in",
	//	Values:     []string{"userNameOne", "userNameTwo", "testUserName"},
	//}
	//filterTwo := root.Filter{
	//	Criterion:  "UserName",
	//	Comparison: "not in",
	//	Values:     []string{"userNameOne", "userNameTwo", "userNameThree"},
	//}
	//goodMatch := filterUserName(user, &filterOne)
	//if !goodMatch {
	//	t.Error("match on existing username 'in' list returned false")
	//}
	//noMatch := filterUserName(user, &filterTwo)
	//if !noMatch {
	//	t.Error("match on missing username 'not in' list returned true")
	//}

}

func TestEnforcePasswordPolicy(t *testing.T) {

	var err error
	var sysLogger *syslog.Writer
	sysLogger, err = syslog.Dial("", "", syslog.LOG_DEBUG, "ape")
	var l []interface{}
	l = append(l, sysLogger)
	if err != nil {
		fmt.Println(err)
	}
	mockSvc := &MockIAMClient{}
	filter := root.Filter{
		Criterion:  "MinimumPasswordLength",
		Comparison: ">=",
		Value:      "14",
	}
	planItem := PlanItem{
		ID: "testId",
		Target: planItemTarget{
			AccountID:    "1234567890",
			AccountAlias: "alias",
			ExternalID:   "extId",
			Regions:      []string{"region"},
			Role:         "role",
		},
		Policy: root.Policy{
			Resource: "resource",
			Name:     "name",
			Filters:  []root.Filter{filter},
			Actions:  []string{"action"},
			Desc:     "desc",
			Severity: "severity",
		},
	}
	var result enforcePolicyOutput

	result, err = enforcePasswordPolicy(l, mockSvc, planItem)
	if err != nil {
		t.Error("EnforcePasswordPolicy returned an error")
	}
	if !result[0].IssuesFound {
		t.Error("password policy incorrectly didn't return success")
	}
}
