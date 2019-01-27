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

package mocks

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	h "github.com/jonhadfield/ape/helpers"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// assert fails the test if the condition is false.
func assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

// ok fails the test if an err is not nil.
func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

// equals fails the test if exp is not equal to act.
func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

// MOCK IAM CLIENT 1
// Implements:
//   - GetAccountPasswordPolicy
//   - GetLoginProfile
//   - ListMFADevicesOutput
//   - ListMFADevices
//   - ListAccessKeys
//   - GetAccessKeyLastUsed

type MockIAMClient struct {
	iamiface.IAMAPI
}

func (m *MockIAMClient) GetAccountPasswordPolicy(input *iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	trueVal := true
	falseVal := false
	fourteen := int64(14)
	hundred := int64(100)

	passwordPolicy := iam.PasswordPolicy{
		AllowUsersToChangePassword: &falseVal,
		ExpirePasswords:            &falseVal,
		HardExpiry:                 &trueVal,
		MinimumPasswordLength:      &fourteen,
		PasswordReusePrevention:    &fourteen,
		RequireLowercaseCharacters: &falseVal,
		RequireNumbers:             &falseVal,
		RequireSymbols:             &falseVal,
		RequireUppercaseCharacters: &falseVal,
		MaxPasswordAge:             &hundred,
	}

	result := iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &passwordPolicy,
	}
	return &result, nil
}

func (m *MockIAMClient) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	policy := &iam.AttachedPolicy{
		PolicyArn:  h.PtrToStr("arn:aws-trusted-advisor:iam::aws-trusted-advisor:policy/AWSSupportAccess"),
		PolicyName: h.PtrToStr("AWSSupportAccess"),
	}
	var attachedPolicies []*iam.AttachedPolicy
	attachedPolicies = append(attachedPolicies, policy)
	result := iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: attachedPolicies,
	}
	return &result, nil
}

func (m *MockIAMClient) GetLoginProfile(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	now := time.Now().UTC()
	resetRequired := false
	loginProfile := iam.LoginProfile{
		CreateDate:            &now,
		UserName:              h.PtrToStr("Jon"),
		PasswordResetRequired: &resetRequired,
	}
	result := iam.GetLoginProfileOutput{
		LoginProfile: &loginProfile,
	}
	return &result, nil
}

func (m *MockIAMClient) ListMFADevicesOutput(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	now := time.Now().UTC()
	resetRequired := false
	loginProfile := iam.LoginProfile{
		CreateDate:            &now,
		UserName:              h.PtrToStr("Jon"),
		PasswordResetRequired: &resetRequired,
	}
	result := iam.GetLoginProfileOutput{
		LoginProfile: &loginProfile,
	}
	return &result, nil
}

func (m *MockIAMClient) ListMFADevices(input *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {

	now := time.Now().UTC()
	mfaDevice := &iam.MFADevice{
		UserName:     h.PtrToStr("Jon"),
		EnableDate:   &now,
		SerialNumber: h.PtrToStr("serialNo"),
	}

	mfaDevices := []*iam.MFADevice{mfaDevice}
	output := iam.ListMFADevicesOutput{
		MFADevices: mfaDevices,
	}
	return &output, nil
}

func (m *MockIAMClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	now := time.Now().UTC()
	accessKey1Metadata := iam.AccessKeyMetadata{
		UserName:    h.PtrToStr("Jon"),
		CreateDate:  &now,
		AccessKeyId: h.PtrToStr("AKIAIOSFODNN7EXAMPLE"),
		Status:      h.PtrToStr("Active"),
	}

	keys := []*iam.AccessKeyMetadata{
		&accessKey1Metadata,
	}

	output := iam.ListAccessKeysOutput{
		AccessKeyMetadata: keys,
	}
	return &output, nil
}

// MOCK IAM CLIENT 2
// Implements:
//   - ListMFADevices
//   - GetAccessKeyLastUsed

func (m *MockIAMClient) GetAccessKeyLastUsed(input *iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error) {
	now := time.Now().UTC()
	accessKeyLastUsed := iam.AccessKeyLastUsed{
		LastUsedDate: &now,
		Region:       h.PtrToStr("eu-west-1"),
		ServiceName:  h.PtrToStr("ec2"),
	}
	output := iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &accessKeyLastUsed,
		UserName:          h.PtrToStr("Jon"),
	}
	return &output, nil
}

type MockIAMClient2 struct {
	iamiface.IAMAPI
}

func (m *MockIAMClient2) ListMFADevices(input *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	var mfaDevices []*iam.MFADevice
	output := iam.ListMFADevicesOutput{
		MFADevices: mfaDevices,
	}
	return &output, nil
}
