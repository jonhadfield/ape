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

	"encoding/csv"
	"io"
	"strings"
	"time"

	"reflect"

	"strconv"

	"encoding/json"
	"net/url"

	"sync"

	"github.com/Knetic/govaluate"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	ri "github.com/jonhadfield/ape/root/aws/iam"
	"github.com/pkg/errors"
)

type iamUser struct {
	iam.User
	CRUserCreationTime          time.Time
	CRPasswordEnabled           bool
	CRPasswordLastUsed          time.Time
	CRPasswordLastChanged       time.Time
	CRPasswordNextRotation      time.Time
	CRMfaActive                 bool
	CRAccessKey1Active          bool
	CRAccessKey1LastRotated     time.Time
	CRAccessKey1LastUsedDate    time.Time
	CRAccessKey1LastUsedRegion  string
	CRAccessKey1LastUsedService string
	CRAccessKey2Active          bool
	CRAccessKey2LastRotated     time.Time
	CRAccessKey2LastUsedDate    time.Time
	CRAccessKey2LastUsedRegion  string
	CRAccessKey2LastUsedService string
	CRCert1Active               bool
	CRCert1LastRotated          time.Time
	CRCert2Active               bool
	CRCert2LastRotated          time.Time
}

type iamUsers []iamUser

type accessKey struct {
	iam.AccessKeyMetadata
	LastRotated     time.Time
	LastUsedDate    time.Time
	LastUsedRegion  string
	LastUsedService string
}

type accessKeys []accessKey

func getReportItemByArn(arn string, report credentialReport) (result credentialReportItem) {
	for i := range report {
		item := report[i]
		if item.Arn == arn {
			result = item
			break
		}
	}
	return
}

func getReportItemByUserName(userName string, report credentialReport) (result credentialReportItem) {
	for i := range report {
		item := report[i]
		if item.User == userName {
			result = item
			break
		}
	}
	return
}

var allUsersByAccount map[string]iamUsers

func getUsers(svc iamiface.IAMAPI, accountID string) (users iamUsers, err error) {
	if len(allUsersByAccount[accountID]) > 0 {
		// TODO: Log debug/info? "Returning previously generated user list"
		users = allUsersByAccount[accountID]
		return
	}
	var report credentialReport
	report, err = getCredentialReport(svc)
	if err != nil {
		return
	}
	iamUsersOutput, err := svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	var user iamUser
	for _, u := range iamUsersOutput.Users {
		CRByUser := getReportItemByArn(*u.Arn, report)
		user.Arn = u.Arn
		user.CreateDate = u.CreateDate
		user.PasswordLastUsed = u.PasswordLastUsed
		user.Path = u.Path
		user.UserId = u.UserId
		user.UserName = u.UserName
		user.CRUserCreationTime = CRByUser.UserCreationTime
		user.CRPasswordEnabled = CRByUser.PasswordEnabled
		user.CRPasswordLastUsed = CRByUser.PasswordLastUsed
		user.CRPasswordLastChanged = CRByUser.PasswordLastChanged
		user.CRPasswordNextRotation = CRByUser.PasswordNextRotation
		user.CRMfaActive = CRByUser.MfaActive
		user.CRAccessKey1Active = CRByUser.AccessKey1Active
		user.CRAccessKey1LastRotated = CRByUser.AccessKey1LastRotated
		user.CRAccessKey1LastUsedDate = CRByUser.AccessKey1LastUsedDate
		user.CRAccessKey1LastUsedRegion = CRByUser.AccessKey1LastUsedRegion
		user.CRAccessKey1LastUsedService = CRByUser.AccessKey1LastUsedService
		user.CRAccessKey2Active = CRByUser.AccessKey2Active
		user.CRAccessKey2LastRotated = CRByUser.AccessKey2LastRotated
		user.CRAccessKey2LastUsedDate = CRByUser.AccessKey2LastUsedDate
		user.CRAccessKey2LastUsedRegion = CRByUser.AccessKey2LastUsedRegion
		user.CRAccessKey2LastUsedService = CRByUser.AccessKey2LastUsedService
		user.CRCert1Active = CRByUser.Cert1Active
		user.CRCert1LastRotated = CRByUser.Cert1LastRotated
		user.CRCert2Active = CRByUser.Cert2Active
		user.CRCert2LastRotated = CRByUser.Cert2LastRotated
		users = append(users, user)
	}
	// Add root user
	rootItem := getReportItemByUserName("root", report)
	rootUser := iamUser{}
	rootUser.Arn = &rootItem.Arn
	rootUser.CreateDate = &rootItem.UserCreationTime
	rootUser.PasswordLastUsed = &rootItem.PasswordLastUsed
	rootUser.Path = h.PtrToStr("rootPath")
	rootUser.UserId = h.PtrToStr("rootUsedId")
	rootUser.UserName = h.PtrToStr("root")
	rootUser.CRUserCreationTime = rootItem.UserCreationTime
	rootUser.CRPasswordEnabled = rootItem.PasswordEnabled

	rootUser.CRPasswordLastUsed = rootItem.PasswordLastUsed
	rootUser.CRPasswordLastChanged = rootItem.PasswordLastChanged
	rootUser.CRPasswordNextRotation = rootItem.PasswordNextRotation
	rootUser.CRMfaActive = rootItem.MfaActive
	rootUser.CRAccessKey1Active = rootItem.AccessKey1Active
	rootUser.CRAccessKey1LastRotated = rootItem.AccessKey1LastRotated
	rootUser.CRAccessKey1LastUsedDate = rootItem.AccessKey1LastUsedDate
	rootUser.CRAccessKey1LastUsedRegion = rootItem.AccessKey1LastUsedRegion
	rootUser.CRAccessKey1LastUsedService = rootItem.AccessKey1LastUsedService
	rootUser.CRAccessKey2Active = rootItem.AccessKey2Active
	rootUser.CRAccessKey2LastRotated = rootItem.AccessKey2LastRotated
	rootUser.CRAccessKey2LastUsedDate = rootItem.AccessKey2LastUsedDate
	rootUser.CRAccessKey2LastUsedRegion = rootItem.AccessKey2LastUsedRegion
	rootUser.CRAccessKey2LastUsedService = rootItem.AccessKey2LastUsedService
	rootUser.CRCert1Active = rootItem.Cert1Active
	rootUser.CRCert1LastRotated = rootItem.Cert1LastRotated
	rootUser.CRCert2Active = rootItem.Cert2Active
	rootUser.CRCert2LastRotated = rootItem.Cert2LastRotated
	users = append(users, rootUser)
	// TODO: Log debug/info "Setting GLOBAL Users with: %d entries"
	allUsersByAccount[accountID] = users
	return
}

func getMFADevices(svc iamiface.IAMAPI, username string) (devices []*iam.MFADevice, err error) {
	input := iam.ListMFADevicesInput{}
	if username != "" {
		input.UserName = &username
	}
	var output *iam.ListMFADevicesOutput
	output, err = svc.ListMFADevices(&input)
	if err != nil {
		err = errors.WithStack(err)
	}
	devices = output.MFADevices
	return
}

func getAccessKeys(svc iamiface.IAMAPI, user iamUser) (accessKeys accessKeys) {
	input := iam.ListAccessKeysInput{}

	if !reflect.DeepEqual(user, iamUser{}) {
		input.UserName = user.UserName
	}
	list, _ := svc.ListAccessKeys(&input)
	iamKeys := list.AccessKeyMetadata
	for i, iamKey := range iamKeys {
		mergedAccessKey := accessKey{}
		mergedAccessKey.UserName = iamKey.UserName
		mergedAccessKey.CreateDate = iamKey.CreateDate
		mergedAccessKey.Status = iamKey.Status
		mergedAccessKey.AccessKeyId = iamKey.AccessKeyId
		if i == 0 {
			mergedAccessKey.LastUsedDate = user.CRAccessKey1LastUsedDate
			mergedAccessKey.LastRotated = user.CRAccessKey1LastRotated
			mergedAccessKey.LastUsedRegion = user.CRAccessKey1LastUsedRegion
			mergedAccessKey.LastUsedService = user.CRAccessKey1LastUsedService
		} else if i == 1 {
			mergedAccessKey.LastUsedDate = user.CRAccessKey2LastUsedDate
			mergedAccessKey.LastRotated = user.CRAccessKey2LastRotated
			mergedAccessKey.LastUsedRegion = user.CRAccessKey2LastUsedRegion
			mergedAccessKey.LastUsedService = user.CRAccessKey2LastUsedService
		}
		accessKeys = append(accessKeys, mergedAccessKey)

	}
	return
}

func enforceIAMPolicy(l []interface{}, session *session.Session, planItem PlanItem) (result enforcePolicyOutput, err error) {
	var resource string
	_, resource, err = h.GetResourceParts(planItem.Policy.Resource)
	if err != nil {
		return
	}
	svc := getIAMClient(session, planItem.Target.AccountID)
	switch resource {
	case "User":
		result, err = enforceUserPolicy(l, svc, planItem)
		if err != nil {
			return
		}
	case "Role":
		result, err = enforceRolePolicy(l, svc, planItem)
		if err != nil {
			return
		}
	case "Policy":
		result, err = enforcePolicy(l, svc, planItem)
		if err != nil {
			return
		}
	case "PasswordPolicy":
		result, err = enforcePasswordPolicy(l, svc, planItem)
		if err != nil {
			return
		}
	default:
		message := fmt.Sprintf("unhandled resource: iam: %s", resource)
		err = errors.Wrap(err, message)

	}

	return
}

type credentialReportItem struct {
	User                      string
	Arn                       string
	UserCreationTime          time.Time
	PasswordEnabled           bool
	PasswordLastUsed          time.Time
	PasswordLastChanged       time.Time
	PasswordNextRotation      time.Time
	MfaActive                 bool
	AccessKey1Active          bool
	AccessKey1LastRotated     time.Time
	AccessKey1LastUsedDate    time.Time
	AccessKey1LastUsedRegion  string
	AccessKey1LastUsedService string
	AccessKey2Active          bool
	AccessKey2LastRotated     time.Time
	AccessKey2LastUsedDate    time.Time
	AccessKey2LastUsedRegion  string
	AccessKey2LastUsedService string
	Cert1Active               bool
	Cert1LastRotated          time.Time
	Cert2Active               bool
	Cert2LastRotated          time.Time
}

type credentialReport []credentialReportItem

var iamClientByAccount map[string]iamiface.IAMAPI
var iamClientByAccountMutex sync.Mutex

func getIAMClient(session *session.Session, accID string) (output iamiface.IAMAPI) {
	iamClientByAccountMutex.Lock()
	if iamClientByAccount == nil {
		iamClientByAccount = make(map[string]iamiface.IAMAPI)
	}
	if len(s3SClientByAccountAndRegion) == 0 {
		iamClientByAccount = make(map[string]iamiface.IAMAPI)
	}
	if s3SClientByAccountAndRegion[accID] != nil {
		output = iamClientByAccount[accID]
	} else {
		output = iam.New(session)
		iamClientByAccount[accID] = output
	}
	iamClientByAccountMutex.Unlock()
	return
}

func stringToBool(input string) (output bool) {
	if strings.ToLower(input) == "true" {
		output = true
	}
	return
}

func getCredentialReport(svc iamiface.IAMAPI) (output credentialReport, err error) {
	getInput := &iam.GetCredentialReportInput{}
	var report *iam.GetCredentialReportOutput
	genInput := &iam.GenerateCredentialReportInput{}
	var generateCredentialReportOutput *iam.GenerateCredentialReportOutput
	for {
		generateCredentialReportOutput, err = svc.GenerateCredentialReport(genInput)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		if *generateCredentialReportOutput.State != "COMPLETE" {
			time.Sleep(500 * time.Millisecond)
			continue
		} else {
			break
		}
	}
	report, err = svc.GetCredentialReport(getInput)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	reportContent := string(report.Content)

	reader := csv.NewReader(strings.NewReader(reportContent))
	var readErr error
	var record []string
	var credReportItem credentialReportItem
	for {
		record, readErr = reader.Read()
		if len(record) > 0 && record[0] == "user" && record[1] == "arn" {
			continue
		}
		if readErr == io.EOF {
			break
		}
		var userName string
		if record[crUser] == "<root_account>" {
			userName = "root"
		} else {
			userName = record[crUser]
		}
		var (
			passwordEnabled, mfaActive, accessKey1Active, accessKey2Active, cert1Active, cert2Active bool
			userCreationTime, passwordLastUsed, passwordLastChanged, passwordNextRotation,
			accessKey1LastRotated, accessKey1LastUsedDate, accessKey2LastRotated, accessKey2LastUsedDate,
			cert1LastRotated, cert2LastRotated time.Time
		)
		userCreationTime, err = time.Parse(time.RFC3339, record[crUserCreationTime])
		if err != nil {
			userCreationTime = time.Time{}
		}

		passwordEnabled = stringToBool(record[crPasswordEnabled])

		passwordLastUsed, err = time.Parse(time.RFC3339, record[crPasswordLastUsed])
		if err != nil {
			passwordLastUsed = time.Time{}
		}
		passwordLastChanged, err = time.Parse(time.RFC3339, record[crPasswordLastChanged])
		if err != nil {
			passwordLastChanged = time.Time{}
		}

		passwordNextRotation, err = time.Parse(time.RFC3339, record[crPasswordNextRotation])
		if err != nil {
			passwordNextRotation = time.Time{}
		}
		mfaActive = stringToBool(record[crMfaActive])
		accessKey1Active = stringToBool(record[crAccessKey1Active])

		accessKey1LastRotated, err = time.Parse(time.RFC3339, record[crAccessKey1LastRotated])
		if err != nil {
			accessKey1LastRotated = time.Time{}
		}
		accessKey1LastUsedDate, err = time.Parse(time.RFC3339, record[crAccessKey1LastUsedDate])
		if err != nil {
			accessKey1LastUsedDate = time.Time{}
		}
		accessKey2Active = stringToBool(record[crAccessKey2Active])

		accessKey2LastRotated, err = time.Parse(time.RFC3339, record[crAccessKey2LastRotated])
		if err != nil {
			accessKey2LastRotated = time.Time{}
		}
		accessKey2LastUsedDate, err = time.Parse(time.RFC3339, record[crAccessKey2LastUsedDate])
		if err != nil {
			accessKey2LastUsedDate = time.Time{}
		}
		cert1Active = stringToBool(record[crCert1Active])

		cert1LastRotated, err = time.Parse(time.RFC3339, record[crCert1LastRotated])
		if err != nil {
			cert1LastRotated = time.Time{}
		}
		cert2Active = stringToBool(record[crCert2Active])

		cert2LastRotated, err = time.Parse(time.RFC3339, record[crCert2LastRotated])
		if err != nil {
			cert2LastRotated = time.Time{}
			err = nil
		}

		credReportItem = credentialReportItem{
			Arn:                       record[crArn],
			User:                      userName,
			UserCreationTime:          userCreationTime,
			PasswordEnabled:           passwordEnabled,
			PasswordLastUsed:          passwordLastUsed,
			PasswordLastChanged:       passwordLastChanged,
			PasswordNextRotation:      passwordNextRotation,
			MfaActive:                 mfaActive,
			AccessKey1Active:          accessKey1Active,
			AccessKey1LastRotated:     accessKey1LastRotated,
			AccessKey1LastUsedDate:    accessKey1LastUsedDate,
			AccessKey1LastUsedRegion:  record[crAccessKey1LastUsedRegion],
			AccessKey1LastUsedService: record[crAccessKey1LastUsedService],
			AccessKey2Active:          accessKey2Active,
			AccessKey2LastRotated:     accessKey2LastRotated,
			AccessKey2LastUsedDate:    accessKey2LastUsedDate,
			AccessKey2LastUsedRegion:  record[crAccessKey2LastUsedRegion],
			AccessKey2LastUsedService: record[crAccessKey2LastUsedService],
			Cert1Active:               cert1Active,
			Cert1LastRotated:          cert1LastRotated,
			Cert2Active:               cert2Active,
			Cert2LastRotated:          cert2LastRotated,
		}
		output = append(output, credReportItem)
	}
	return
}

func getAccessKeyLastUsed(svc iamiface.IAMAPI, accessKeyID string) (time *time.Time) {
	input := iam.GetAccessKeyLastUsedInput{
		AccessKeyId: &accessKeyID,
	}
	output, _ := svc.GetAccessKeyLastUsed(&input)
	time = output.AccessKeyLastUsed.LastUsedDate
	return
}

func filterUserName(user iamUser, filter *r.Filter) (filterMatch bool) {
	if filter.Comparison == "in" {
		if h.StringInSlice(*user.UserName, filter.Values) {
			filterMatch = true
		}
	} else if filter.Comparison == "not in" {
		if !h.StringInSlice(*user.UserName, filter.Values) {
			filterMatch = true
		}
	} else if filter.Comparison == "==" && *user.UserName == filter.Value {
		filterMatch = true
	} else if filter.Comparison == "!=" && *user.UserName != filter.Value {
		filterMatch = true
	}
	return
}

func filterHasPassword(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	var getLoginProfileOutput *iam.GetLoginProfileOutput
	getLoginProfileInput := &iam.GetLoginProfileInput{
		UserName: user.UserName,
	}
	var hasPassword bool
	// The user with name root cannot be found.
	if *user.UserName == "root" {
		if user.CRPasswordEnabled {
			hasPassword = true
		}
	} else {
		getLoginProfileOutput, err = svc.GetLoginProfile(getLoginProfileInput)
		if err != nil {
			// NoSuchEntity means no profile, not a failure. everything else will be though.
			if !strings.Contains(err.Error(), "NoSuchEntity") {
				err = errors.WithStack(err)
				return
			}
			// reset error as we don't consider it a failure
			err = nil
		}
		if getLoginProfileOutput.LoginProfile != nil {
			hasPassword = true
		}
	}
	if filter.Value == "false" && !hasPassword {
		filterMatch = true
	}
	if filter.Value == "true" && hasPassword {
		filterMatch = true
	}
	return
}

func filterHasGroup(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	var listGroupsForUserInput = iam.ListGroupsForUserInput{
		UserName: user.UserName,
	}
	var listGroupsForUserOutput *iam.ListGroupsForUserOutput
	listGroupsForUserOutput, err = svc.ListGroupsForUser(&listGroupsForUserInput)
	for _, group := range listGroupsForUserOutput.Groups {
		if *group.GroupName == filter.Value {
			filterMatch = true
			break
		}
	}
	return
}

func filterDoesNotHaveGroup(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	var listGroupsForUserInput = iam.ListGroupsForUserInput{
		UserName: user.UserName,
	}
	var listGroupsForUserOutput *iam.ListGroupsForUserOutput
	listGroupsForUserOutput, err = svc.ListGroupsForUser(&listGroupsForUserInput)
	filterMatch = true
	for _, group := range listGroupsForUserOutput.Groups {
		if *group.GroupName == filter.Value {
			filterMatch = false
			break
		}
	}
	return
}

func filterHasHardwareMFADevice(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	// Lack of virtual MFA doesn't necessarily mean no MFA, so first check the user has MFA
	var hasMFA bool
	hasMFAfilter := &r.Filter{
		Criterion: "HasMFADevice",
		Value:     "true",
	}
	hasMFA, err = filterHasMFADevice(svc, user, hasMFAfilter)
	if err != nil {
		return
	}
	var hasHardwareMFA bool
	if hasMFA {
		// Get all VIRTUAL MFA devices
		var virtualMFADevicesOutput *iam.ListVirtualMFADevicesOutput
		virtualMFADevicesOutput, err = svc.ListVirtualMFADevices(&iam.ListVirtualMFADevicesInput{})
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		virtualMFADevices := virtualMFADevicesOutput.VirtualMFADevices
		hasVirtualMFA := false
		for _, vmd := range virtualMFADevices {
			// Check for root virtual
			if *user.UserName == "root" && strings.HasSuffix(*vmd.SerialNumber, "mfa/root-account-mfa-device") {
				hasVirtualMFA = true
				break
			}
			if vmd.User != nil && *vmd.User.Arn == *user.Arn {
				hasVirtualMFA = true
			}
		}

		if !hasVirtualMFA {
			hasHardwareMFA = true
		}
	}

	if filter.Value == "false" && !hasHardwareMFA {
		filterMatch = true
	}
	if filter.Value == "true" && hasHardwareMFA {
		filterMatch = true
	}
	return
}

func filterHasMFADevice(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	hasMFADevice := "false"
	if *user.UserName == "root" {
		if user.CRMfaActive {
			hasMFADevice = "true"
		}
	} else {
		var devices []*iam.MFADevice
		devices, err = getMFADevices(svc, *user.UserName)
		if err != nil {
			return
		}
		if len(devices) > 0 {
			hasMFADevice = "true"
		}
	}
	if filter.Value == "false" && hasMFADevice == "false" {
		filterMatch = true
	}
	if filter.Value == "true" && hasMFADevice == "true" {
		filterMatch = true
	}
	return
}

func filterPasswordLastUsed(user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	var filterValue time.Time
	filterValue, err = r.ProcessTimeFilterValue(filter)
	if err != nil {
		return
	}
	if user.PasswordLastUsed != nil && !user.PasswordLastUsed.IsZero() {
		passwordLastUsed := user.PasswordLastUsed.In(loc)
		expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", filter.Comparison)
		var expression *govaluate.EvaluableExpression
		expression, err = govaluate.NewEvaluableExpression(expressionTxt)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		parameters := make(map[string]interface{}, 8)
		parameters["lastUsed"] = passwordLastUsed.Unix()
		parameters["filterValue"] = filterValue.Unix()
		result, _ := expression.Evaluate(parameters)
		if result == true {
			filterMatch = true
		}
	}
	return
}

type filterActiveAccessKeysLastUsedInput struct {
	svc    iamiface.IAMAPI
	user   iamUser
	filter *r.Filter
}

func filterActiveAccessKeysLastUsed(input *filterActiveAccessKeysLastUsedInput) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	var filterValue time.Time
	filterValue, err = r.ProcessTimeFilterValue(input.filter)
	if err != nil {
		return
	}

	keys := getAccessKeys(input.svc, input.user)
	for _, key := range keys {
		if *key.Status == "Active" {
			// Check if key last used > or < date
			var keyLastUsed *time.Time
			// Have to process root access keys separately
			switch *key.AccessKeyId {
			case "accessKey1":
				keyLastUsed = &input.user.CRAccessKey1LastUsedDate
			case "accessKey2":
				keyLastUsed = &input.user.CRAccessKey2LastUsedDate
			default:
				keyLastUsed = getAccessKeyLastUsed(input.svc, *key.AccessKeyId)
			}

			if keyLastUsed != nil {
				keyLastUsedConverted := keyLastUsed.In(loc)
				expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", input.filter.Comparison)
				expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
				parameters := make(map[string]interface{}, 8)
				parameters["lastUsed"] = keyLastUsedConverted.Unix()
				parameters["filterValue"] = filterValue.Unix()
				result, _ := expression.Evaluate(parameters)
				if result == true {
					filterMatch = true
					break
				}
			}

		}
	}
	return
}

func filterActiveAccessKeysLastRotated(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	var filterValue time.Time
	filterValue, err = r.ProcessTimeFilterValue(filter)

	keys := getAccessKeys(svc, user)
	for _, key := range keys {
		if *key.Status == "Active" {
			// If the check is to see if last rotated greater than a certain time, then check the key is that age yet
			var lastRotatedMatch bool
			if filter.Comparison == ">" {
				// Check if key created > or < date
				keyCreated := key.CreateDate.In(loc)
				kcExpressionTxt := fmt.Sprintf("(filterValue %s created)", filter.Comparison)
				kcExpression, _ := govaluate.NewEvaluableExpression(kcExpressionTxt)
				kcParameters := make(map[string]interface{}, 8)
				kcParameters["created"] = keyCreated.Unix()
				kcParameters["filterValue"] = filterValue.Unix()
				kcResult, _ := kcExpression.Evaluate(kcParameters)
				if kcResult != true {
					continue
				}
			}

			// Check if key last rotated > or < date
			keyLastRotated := key.LastRotated.In(loc)
			klrExpressionTxt := fmt.Sprintf("(filterValue %s lastRotated)", filter.Comparison)
			klrExpression, _ := govaluate.NewEvaluableExpression(klrExpressionTxt)
			klrParameters := make(map[string]interface{}, 8)
			klrParameters["lastRotated"] = keyLastRotated.Unix()
			klrParameters["filterValue"] = filterValue.Unix()
			klrResult, _ := klrExpression.Evaluate(klrParameters)
			if klrResult == true {
				lastRotatedMatch = true
			}

			if lastRotatedMatch {
				filterMatch = true
				break
			}

		}
	}
	return
}

func filterHasActiveAccessKeyCreatedWithUser(svc iamiface.IAMAPI, user iamUser) (filterMatch bool, err error) {
	keys := getAccessKeys(svc, user)
	for _, key := range keys {
		if *key.CreateDate == *user.CreateDate {
			filterMatch = true
			return
		}
	}
	return
}

func getRootKeys(user iamUser) (keys accessKeys) {
	key1 := accessKey{
		LastRotated:     user.CRAccessKey1LastRotated,
		LastUsedRegion:  user.CRAccessKey1LastUsedRegion,
		LastUsedService: user.CRAccessKey1LastUsedService,
		LastUsedDate:    user.CRAccessKey1LastUsedDate,
	}
	if user.CRAccessKey1Active {
		key1.Status = h.PtrToStr("Active")
	} else {
		key1.Status = h.PtrToStr("Inactive")
	}
	keys = append(keys, key1)
	key2 := accessKey{
		LastRotated:     user.CRAccessKey2LastRotated,
		LastUsedRegion:  user.CRAccessKey2LastUsedRegion,
		LastUsedService: user.CRAccessKey2LastUsedService,
		LastUsedDate:    user.CRAccessKey2LastUsedDate,
	}
	if user.CRAccessKey1Active {
		key2.Status = h.PtrToStr("Active")
	} else {
		key2.Status = h.PtrToStr("Inactive")
	}
	keys = append(keys, key2)
	return
}

func filterHasActiveAccessKey(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	var keys accessKeys
	if *user.UserName == "root" {
		keys = getRootKeys(user)
	} else {
		keys = getAccessKeys(svc, user)
	}

	var wanted bool
	wanted, err = strconv.ParseBool(filter.Value)
	if err != nil {
		return
	}
	foundActive := false
	for _, key := range keys {
		if *key.Status == "Active" {
			foundActive = true
			break
		}
	}
	if wanted && foundActive {
		filterMatch = true
	}
	if !wanted && !foundActive {
		filterMatch = true
	}
	return
}

func filterHasUnusedActiveAccessKey(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	var keys accessKeys
	if *user.UserName == "root" {
		key1 := accessKey{
			LastRotated:     user.CRAccessKey1LastRotated,
			LastUsedRegion:  user.CRAccessKey1LastUsedRegion,
			LastUsedService: user.CRAccessKey1LastUsedService,
			LastUsedDate:    user.CRAccessKey1LastUsedDate,
		}
		if user.CRAccessKey1Active {
			key1.Status = h.PtrToStr("Active")
		} else {
			key1.Status = h.PtrToStr("Inactive")
		}
		keys = append(keys, key1)
		key2 := accessKey{
			LastRotated:     user.CRAccessKey2LastRotated,
			LastUsedRegion:  user.CRAccessKey2LastUsedRegion,
			LastUsedService: user.CRAccessKey2LastUsedService,
			LastUsedDate:    user.CRAccessKey2LastUsedDate,
		}
		if user.CRAccessKey1Active {
			key2.Status = h.PtrToStr("Active")
		} else {
			key2.Status = h.PtrToStr("Inactive")
		}
		keys = append(keys, key2)
	} else {
		keys = getAccessKeys(svc, user)
	}

	var wanted bool
	wanted, err = strconv.ParseBool(filter.Value)
	if err != nil {
		return
	}
	foundUnusedActive := false
	for _, key := range keys {
		if *key.Status == "Active" && key.LastUsedDate.IsZero() {
			foundUnusedActive = true
			break
		}
	}
	if wanted && foundUnusedActive {
		filterMatch = true
	}
	if !wanted && !foundUnusedActive {
		filterMatch = true
	}
	return
}

var passwordPolicy = map[string]*iam.GetAccountPasswordPolicyOutput{}

func getAccountPasswordPolicy(svc iamiface.IAMAPI, accountid string) (output *iam.GetAccountPasswordPolicyOutput, err error) {
	if passwordPolicy[accountid] != nil {
		output = passwordPolicy[accountid]
	} else {
		output, err = svc.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		passwordPolicy[accountid] = output
	}
	return
}

func filterPasswordPolicy(svc iamiface.IAMAPI, planItem PlanItem) (filtersMatch bool, err error) {
	accountID := planItem.Target.AccountID
	var getPolicyOutput *iam.GetAccountPasswordPolicyOutput
	getPolicyOutput, err = getAccountPasswordPolicy(svc, accountID)
	if err != nil {
		return
	}

	var filterMatch bool
	for _, filter := range planItem.Policy.Filters {

		filterMatch = false
		switch filter.Criterion {
		case "MinimumPasswordLength":
			expressionTxt := fmt.Sprintf("(minimumPasswordLength %s filterValue)", filter.Comparison)
			expression, govaluateErr := govaluate.NewEvaluableExpression(expressionTxt)
			if govaluateErr != nil {
				err = govaluateErr
				return
			}
			parameters := make(map[string]interface{}, 8)
			parameters["minimumPasswordLength"] = *getPolicyOutput.PasswordPolicy.MinimumPasswordLength
			filterVal, _ := strconv.Atoi(filter.Value)
			parameters["filterValue"] = filterVal
			result, evalErr := expression.Evaluate(parameters)
			if evalErr != nil {
				err = evalErr
				return
			}
			if result == true {
				filterMatch = true
			}
		case "RequireAtLeastOneUpperCaseLetter":
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.RequireUppercaseCharacters == filterValue {
				filterMatch = true
			}
		case "RequireAtLeastOneLowerCaseLetter":
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.RequireLowercaseCharacters == filterValue {
				filterMatch = true
			}
		case "RequireAtLeastOneNumber":
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.RequireNumbers == filterValue {
				filterMatch = true
			}
		case "RequireAtLeastOneNonAlphanumericCharacter":
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.RequireSymbols == filterValue {
				filterMatch = true

			}
		case "AllowUsersToChangeTheirOwnPassword":
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.AllowUsersToChangePassword == filterValue {
				filterMatch = true
			}
		case "PasswordExpirationPeriod":
			maxPasswordAge := getPolicyOutput.PasswordPolicy.MaxPasswordAge
			onemillion := int64(1000000)
			if maxPasswordAge == nil {
				maxPasswordAge = &onemillion
			}
			expressionTxt := fmt.Sprintf("(expirationPeriod %s filterValue)", filter.Comparison)
			var expression *govaluate.EvaluableExpression
			expression, err = govaluate.NewEvaluableExpression(expressionTxt)
			if err != nil {
				return
			}
			parameters := make(map[string]interface{}, 8)
			parameters["expirationPeriod"] = *maxPasswordAge
			var filterVal int
			filterVal, err = strconv.Atoi(filter.Value)
			if err != nil {
				return
			}
			parameters["filterValue"] = filterVal
			var result interface{}
			result, err = expression.Evaluate(parameters)
			if err != nil {
				return
			}
			if result == true {
				filterMatch = true
			}
		case "NumberOfPasswordsToRemember":
			expressionTxt := fmt.Sprintf("(passwordsToRemember %s filterValue)", filter.Comparison)
			var expression *govaluate.EvaluableExpression
			expression, err = govaluate.NewEvaluableExpression(expressionTxt)
			if err != nil {
				return
			}
			parameters := make(map[string]interface{}, 8)

			passwordsToRemember := getPolicyOutput.PasswordPolicy.PasswordReusePrevention
			zero := int64(0)
			if passwordsToRemember == nil {
				passwordsToRemember = &zero
			}
			parameters["passwordsToRemember"] = *passwordsToRemember
			var filterVal int
			filterVal, err = strconv.Atoi(filter.Value)
			if err != nil {
				return
			}
			parameters["filterValue"] = filterVal
			var result interface{}
			result, err = expression.Evaluate(parameters)
			if err != nil {
				return
			}
			if result == true {
				filterMatch = true

			}
		case "ExpirationRequiresAdministratorReset":
			// imp:iam:PasswordPolicy:ExpirationRequiresAdministratorReset
			filterValue, _ := strconv.ParseBool(filter.Value)
			if *getPolicyOutput.PasswordPolicy.HardExpiry == filterValue {
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
	return
}

func filterActiveAccessKeysAge(svc iamiface.IAMAPI, user iamUser, filter *r.Filter) (filterMatch bool, err error) {
	loc, _ := time.LoadLocation("UTC")
	var filterValue time.Time
	filterValue, err = r.ProcessTimeFilterValue(filter)
	if err != nil {
		return
	}
	keys := getAccessKeys(svc, user)
	for _, key := range keys {
		if *key.Status == "Active" {
			// Check if key age > or < date
			keyCreated := key.CreateDate.In(loc)
			expressionTxt := fmt.Sprintf("(filterValue %s lastUsed)", filter.Comparison)
			expression, _ := govaluate.NewEvaluableExpression(expressionTxt)
			parameters := make(map[string]interface{}, 8)
			parameters["lastUsed"] = keyCreated.Unix()
			parameters["filterValue"] = filterValue.Unix()
			result, _ := expression.Evaluate(parameters)
			if result == true {
				filterMatch = true
				break
			}
		}
	}
	return
}

func filterHasPolicies(svc iamiface.IAMAPI, user iamUser, filter *r.Filter, policyType string) (filterMatch bool, err error) {
	if *user.UserName != "root" {
		var hasPolicies bool
		if policyType == "user" {
			var listUserPoliciesOutput *iam.ListUserPoliciesOutput
			listUserPoliciesOutput, err = svc.ListUserPolicies(&iam.ListUserPoliciesInput{
				UserName: user.UserName,
			})
			if len(listUserPoliciesOutput.PolicyNames) > 0 {
				hasPolicies = true
			}
		} else if policyType == "managed" {
			var listAttachedUserPoliciesOutput *iam.ListAttachedUserPoliciesOutput
			listAttachedUserPoliciesOutput, err = svc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
				UserName: user.UserName,
			})
			if len(listAttachedUserPoliciesOutput.AttachedPolicies) > 0 {
				hasPolicies = true
			}
		}

		if filter.Value == "true" && hasPolicies {
			filterMatch = true
		}
		if filter.Value == "false" && !hasPolicies {
			filterMatch = true
		}
	}
	return
}

func filterHasManagedPolicyAttached(svc iamiface.IAMAPI, role iam.Role, filter *r.Filter) (filterMatch bool, err error) {
	var listAttachedRolePoliciesInput = &iam.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	}
	var listAttachedRolePoliciesOutput *iam.ListAttachedRolePoliciesOutput
	listAttachedRolePoliciesOutput, err = svc.ListAttachedRolePolicies(listAttachedRolePoliciesInput)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	for _, policy := range listAttachedRolePoliciesOutput.AttachedPolicies {
		if filter.Comparison == "in" {
			if h.StringInSlice(*policy.PolicyArn, filter.Values) ||
				h.StringInSliceContents(*policy.PolicyArn, filter.Values) {
				filterMatch = true
				break
			}
		}
	}
	return
}

func processIAMErrors(l []interface{}, err error, planItem PlanItem) (outputErr policyItemOutputError) {
	h.Debug(l, "processing IAM errors")
	if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
		_, resource, _ := h.GetResourceParts(planItem.Policy.Resource)
		switch resource {
		case "User":
			if strings.Contains(awsErr.Message(), "iam:ListUsers") {
				outputErr = policyItemOutputError{message: fmt.Sprintf("failed: missing required permission \"iam:ListUsers\" on resource \"arn:aws-trusted-advisor:iam::%s:user/\" to run this policy", planItem.Target.AccountID), error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:GenerateCredentialReport") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:GenerateCredentialReport\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:GetCredentialReport") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:GetCredentialReport\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:GetLoginProfile") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:GetLoginProfile\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListUserPolicies") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListUserPolicies\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListVirtualMFADevices") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListVirtualMFADevices\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListAttachedUserPolicies") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListAttachedUserPolicies\"", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListMFADevices") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListMFADevices\"", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		case "Policy":
			if strings.Contains(awsErr.Message(), "iam:ListPolicies") {
				outputErr = policyItemOutputError{message: fmt.Sprintf("failed: missing required permission \"iam:ListPolicies\" on resource \"arn:aws-trusted-advisor:iam::%s:policy/\" to run this policy", planItem.Target.AccountID), error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListPolicyVersions") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListPolicyVersions\" to run this policy", error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:GetPolicyVersion") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:GetPolicyVersion\" to run this policy", error: err, level: "error"}
			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		case "Role":
			if strings.Contains(awsErr.Message(), "iam:ListRoles") {
				outputErr = policyItemOutputError{message: fmt.Sprintf("failed: missing permission \"iam:ListRoles\" on resource \"arn:aws-trusted-advisor:iam::%s:role/\" to run this policy", planItem.Target.AccountID), error: err, level: "error"}
			} else if strings.Contains(awsErr.Message(), "iam:ListAttachedRolePolicies") {
				outputErr = policyItemOutputError{message: "failed: missing required permission \"iam:ListAttachedRolePolicies\"", error: err, level: "error"}

			} else {
				outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
			}
		}
	} else {
		outputErr = policyItemOutputError{message: "failed: unhandled exception", error: err, level: "error"}
	}

	return
}

func enforceUserPolicy(l []interface{}, svc iamiface.IAMAPI, planItem PlanItem) (output enforcePolicyOutput, err error) {
	h.Debug(l, "enforcing user policy")
	var outputErr policyItemOutputError
	if allUsersByAccount == nil {
		allUsersByAccount = make(map[string]iamUsers)
	}
	var users iamUsers
	users, err = getUsers(svc, planItem.Target.AccountID)
	if err != nil {
		outputErr = processIAMErrors(l, err, planItem)
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: true,
			OutputErr:   outputErr,
		})
		logPolicyOutputItemError(l, outputErr)
		return
	}

	var anyFiltersMatch bool
	for i := range users {
		user := users[i]
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*user.Arn, *user.UserId, *user.UserName},
		}) {
			continue
		}
		var filterMatch, filtersMatch bool
		for _, filter := range planItem.Policy.Filters {
			filterMatch = false
			switch filter.Criterion {
			case "UserName":
				filterMatch = filterUserName(user, &filter)
			case "HasPassword":
				filterMatch, err = filterHasPassword(svc, user, &filter)
			case "HasGroup":
				if *user.UserName == "root" {
					continue
				}
				filterMatch, err = filterHasGroup(svc, user, &filter)
			case "DoesNotHaveGroup":
				if *user.UserName == "root" {
					continue
				}
				filterMatch, err = filterDoesNotHaveGroup(svc, user, &filter)
			case "HasMFADevice":
				filterMatch, err = filterHasMFADevice(svc, user, &filter)
			case "HasHardwareMFADevice":
				filterMatch, err = filterHasHardwareMFADevice(svc, user, &filter)
			case "HasActiveAccessKey":
				filterMatch, err = filterHasActiveAccessKey(svc, user, &filter)
			case "HasInlinePolicies":
				filterMatch, err = filterHasPolicies(svc, user, &filter, "user")
			case "HasManagedPolicies":
				filterMatch, err = filterHasPolicies(svc, user, &filter, "managed")
			case "PasswordLastUsed":
				filterMatch, err = filterPasswordLastUsed(user, &filter)
			case "HasActiveAccessKeyCreatedWithUser":
				filterMatch, err = filterHasActiveAccessKeyCreatedWithUser(svc, user)
			case "HasUnusedActiveAccessKey":
				filterMatch, err = filterHasUnusedActiveAccessKey(svc, user, &filter)
			case "ActiveAccessKeysLastUsed":
				filterInput := filterActiveAccessKeysLastUsedInput{
					svc:    svc,
					user:   user,
					filter: &filter,
				}
				filterMatch, err = filterActiveAccessKeysLastUsed(&filterInput)
			case "ActiveAccessKeysAge":
				filterMatch, err = filterActiveAccessKeysAge(svc, user, &filter)
			case "ActiveAccessKeysLastRotated":
				filterMatch, err = filterActiveAccessKeysLastRotated(svc, user, &filter)
			default:
				err = fmt.Errorf("criterion: \"%s\" is not implemented, yet exists in catalogue. Oops", filter.Criterion)
				return
			}
			if err != nil {
				outputErr = processIAMErrors(l, err, planItem)
				output = appendPolicyOutput(l, output, createPolicyOutputInput{
					PlanItem:    planItem,
					IssuesFound: true,
					OutputErr:   outputErr,
				})
				logPolicyOutputItemError(l, outputErr)
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
			for _, action := range planItem.Policy.Actions {
				switch strings.ToLower(action) {
				case "report":
					// TODO: Output the affected items, e.g. access key ids
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:     planItem,
						ResourceName: *user.UserName,
						ResourceArn:  *user.Arn,
						IssuesFound:  true,
					})
				}
			}
		} // end if filtersMatch
	} // end user
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}

func enforcePasswordPolicy(l []interface{}, svc iamiface.IAMAPI, planItem PlanItem) (output enforcePolicyOutput, err error) {
	var filtersMatch bool
	filtersMatch, err = filterPasswordPolicy(svc, planItem)
	var policyMissing bool

	var outputErr policyItemOutputError
	if err != nil {
		outputErr = processIAMErrors(l, err, planItem)
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: true,
			OutputErr:   outputErr,
		})
		logPolicyOutputItemError(l, outputErr)
		return
	}
	if filtersMatch || policyMissing {
		var message string
		if policyMissing {
			message = "policy does not exist"
		}
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			ResourceArn: "",
			Message:     message,
			IssuesFound: true,
		})
	} else {
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: false,
		})
	}
	return
}

var allRolesByAccountID map[string][]iam.Role

func getRoles(svc iamiface.IAMAPI, accountID string) (roles []iam.Role, err error) {
	if len(allRolesByAccountID[accountID]) > 0 {
		// TODO: Log debug/info? "Returning previously generated roles list"
		roles = allRolesByAccountID[accountID]
		return
	}

	iamRolesOutput, err := svc.ListRoles(&iam.ListRolesInput{})
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	for _, iamRole := range iamRolesOutput.Roles {
		roles = append(roles, *iamRole)
	}
	// TODO: Log debug/info "Setting GLOBAL Roles with: %d entries"
	allRolesByAccountID[accountID] = roles
	return
}

var allPoliciesByAccount map[string][]iam.Policy

func getPolicies(svc iamiface.IAMAPI, accountID string) (policies []iam.Policy, err error) {
	if len(allPoliciesByAccount[accountID]) > 0 {
		// TODO: Log debug/info? "Returning previously generated policies list"
		policies = allPoliciesByAccount[accountID]
		return
	}
	scope := "Local"
	var marker string
	for {
		var input *iam.ListPoliciesInput
		if marker != "" {
			input = &iam.ListPoliciesInput{
				Marker: &marker,
				Scope:  &scope,
			}
		} else {
			input = &iam.ListPoliciesInput{
				Scope: &scope,
			}
		}
		var iamPoliciesOutput *iam.ListPoliciesOutput
		iamPoliciesOutput, err = svc.ListPolicies(input)
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		for _, iamPolicy := range iamPoliciesOutput.Policies {
			policies = append(policies, *iamPolicy)
		}

		if !*iamPoliciesOutput.IsTruncated {
			// TODO: Log debug/info "Setting GLOBAL Policies with: %d entries"
			allPoliciesByAccount[accountID] = policies
			return
		}

	}

}

func filterRoleName(role iam.Role, filter *r.Filter) (filterMatch bool) {
	if filter.Comparison == "contains" {
		if strings.Contains(*role.RoleName, filter.Value) {
			filterMatch = true
		}
	}
	if filter.Comparison == "in" {
		if h.StringInSlice(*role.RoleName, filter.Values) {
			filterMatch = true
		}
	}
	if filter.Comparison == "not in" {
		if !h.StringInSlice(*role.RoleName, filter.Values) {
			filterMatch = true
		}
	}
	return
}

func enforceRolePolicy(l []interface{}, svc iamiface.IAMAPI, planItem PlanItem) (output enforcePolicyOutput, err error) {
	var outputErr policyItemOutputError
	if allRolesByAccountID == nil {
		allRolesByAccountID = make(map[string][]iam.Role)
	}
	// Create IAM client
	var roles []iam.Role
	roles, err = getRoles(svc, planItem.Target.AccountID)
	if err != nil {
		outputErr = processIAMErrors(l, err, planItem)
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: true,
			OutputErr:   outputErr,
		})
		logPolicyOutputItemError(l, outputErr)
		return
	}
	var anyFiltersMatch bool
	for _, role := range roles {
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*role.Arn, *role.RoleId, *role.RoleName},
		}) {
			continue
		}
		var filterMatch, filtersMatch bool
		for _, filter := range planItem.Policy.Filters {
			filterMatch = false
			switch filter.Criterion {
			case "RoleName":
				// imp:iam:Role:RoleName
				filterMatch = filterRoleName(role, &filter)
			case "HasManagedPolicyAttached":
				filterMatch, err = filterHasManagedPolicyAttached(svc, role, &filter)
			default:
				err = fmt.Errorf("criterion: \"%s\" is not implemented, yet exists in catalogue. Oops", filter.Criterion)
				return
			}
			if err != nil {
				outputErr = processIAMErrors(l, err, planItem)
				output = appendPolicyOutput(l, output, createPolicyOutputInput{
					PlanItem:    planItem,
					IssuesFound: true,
					OutputErr:   outputErr,
				})
				logPolicyOutputItemError(l, outputErr)
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
					// TODO: Output the affected items, e.g. access key ids
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:     planItem,
						ResourceName: *role.RoleName,
						ResourceArn:  *role.Arn,
						IssuesFound:  issuesFound,
					})
				}
			}
		} // end if filtersMatch
	} // end user
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}

func parseIAMPolicyDocument(document string) (statements []ri.PolicyStatement, err error) {
	var policyDocument ri.RawPolicyDocument
	var decodedDocument string
	decodedDocument, err = url.QueryUnescape(document)
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(decodedDocument), &policyDocument)
	if err != nil {
		return
	}
	rawStatements := string(policyDocument.Statement[:])
	var policyStatement ri.RawStatementEntry
	var policyStatements []ri.RawStatementEntry
	// try unmarshalling array of statements
	errArr := json.Unmarshal([]byte(rawStatements), &policyStatements)
	if errArr != nil {
		// try unmarshalling single statement instead
		errSin := json.Unmarshal([]byte(rawStatements), &policyStatement)
		if errSin != nil {
			return
		}
		policyStatements = append(policyStatements, policyStatement)
	}

	for _, ps := range policyStatements {
		// *** RESOURCES
		var resources []string
		if string(ps.Resource[:]) != "" {
			var singleResource string
			var multipleResources []string
			err = json.Unmarshal(ps.Resource, &singleResource)
			if err != nil {
				err = json.Unmarshal(ps.Resource, &multipleResources)
				if err != nil {
					return
				}
				resources = append(resources, multipleResources...)
			} else {
				resources = append(resources, singleResource)
			}
		}

		// *** ACTIONS
		var actions []string
		if string(ps.Action[:]) != "" {
			// try unmarshalling action to single string
			var singleAction string
			var multipleActions []string
			err = json.Unmarshal(ps.Action, &singleAction)
			if err != nil {
				err = json.Unmarshal(ps.Action, &multipleActions)
				if err != nil {
					return
				}
				actions = append(actions, multipleActions...)
			} else {
				actions = append(actions, singleAction)
			}
		}

		var pse = ri.PolicyStatement{
			Effect:   ps.Effect,
			Resource: resources,
			Action:   actions,
		}
		statements = append(statements, pse)
	}
	return
}

func checkPolicyDocumentsAgainstFilters(svc iamiface.IAMAPI, policy iam.Policy, filters []r.Filter) (result bool, err error) {
	// TODO: Allow filter to specify if 'default' or 'all' versions to be checked
	listPolicyVersionsOutput, err := svc.ListPolicyVersions(&iam.ListPolicyVersionsInput{
		PolicyArn: policy.Arn,
	})
	if err != nil {
		err = errors.WithStack(err)
		return

	}
	var useVersion *string
	for _, filter := range filters {
		if filter.Criterion == "Version" && filter.Value == "Default" {
			useVersion = policy.DefaultVersionId
		}
	}
	for _, policyVersion := range listPolicyVersionsOutput.Versions {
		if useVersion != nil && *useVersion != *policyVersion.VersionId {
			continue
		}
		var policyVersionOutput *iam.GetPolicyVersionOutput
		policyVersionOutput, err = svc.GetPolicyVersion(&iam.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: policyVersion.VersionId,
		})
		if err != nil {
			err = errors.WithStack(err)
			return
		}
		document := *policyVersionOutput.PolicyVersion.Document
		var statements []ri.PolicyStatement
		statements, err = parseIAMPolicyDocument(document)
		if err != nil {
			return
		}
		for _, statementEntry := range statements {
			var filterMatch, filtersMatch bool
			for _, filter := range filters {
				if filter.Criterion == "Version" {
					continue
				}
				filterMatch = false
				if h.StringInSlice(filter.Criterion, policyDocumentDetailCriteria) {
					if filter.Criterion == "Effect" && filter.Value == statementEntry.Effect {
						filterMatch = true
					}
					if filter.Criterion == "Action" {
						if h.StringInSlice(filter.Value, statementEntry.Action) {
							filterMatch = true
						}
					}
					if filter.Criterion == "Resource" {
						if h.StringInSlice(filter.Value, statementEntry.Resource) {
							filterMatch = true
						}
					}
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
				result = true
				return
			}
		}

	}
	return
}

var policyDetailCriteria = []string{"PolicyName", "CreateDate", "Description", "IsAttachment", "UpdateDate"}
var policyDocumentDetailCriteria = []string{"Version", "Effect", "Resource", "Action"}

func enforcePolicy(l []interface{}, svc iamiface.IAMAPI, planItem PlanItem) (output enforcePolicyOutput, err error) {
	var outputErr policyItemOutputError
	if allPoliciesByAccount == nil {
		allPoliciesByAccount = make(map[string][]iam.Policy)
	}
	// Create IAM client
	var policies []iam.Policy
	policies, err = getPolicies(svc, planItem.Target.AccountID)
	if err != nil {
		outputErr = processIAMErrors(l, err, planItem)
		output = appendPolicyOutput(l, output, createPolicyOutputInput{
			PlanItem:    planItem,
			IssuesFound: true,
			OutputErr:   outputErr,
		})
		logPolicyOutputItemError(l, outputErr)
		return
	}
	var anyFiltersMatch bool
	var policyDocumentsChecked bool

	for _, policy := range policies {
		if isIgnored(isIgnoredInput{
			planItem:    planItem,
			resourceIDs: []string{*policy.Arn, *policy.PolicyName, *policy.PolicyId},
		}) {
			continue
		}
		policyDocumentsChecked = false
		var filterMatch, filtersMatch bool
		for _, filter := range planItem.Policy.Filters {
			if h.StringInSlice(filter.Criterion, policyDetailCriteria) {
				// Check policy detail
				switch filter.Criterion {
				case "PolicyName":
					filterMatch = true
				}
			} else if !policyDocumentsChecked && h.StringInSlice(filter.Criterion, policyDocumentDetailCriteria) {
				// Check policy documents against all filters and marked as already checked
				filterMatch, err = checkPolicyDocumentsAgainstFilters(svc, policy, planItem.Policy.Filters)
				policyDocumentsChecked = true
			} else if !h.StringInSlice(filter.Criterion, policyDocumentDetailCriteria) && !h.StringInSlice(filter.Criterion, policyDetailCriteria) {
				err = errors.New("policy filter doesn't match either Version, DetailCriteria nor DocumentDetailCriteria.")
				if err != nil {
					outputErr = processIAMErrors(l, err, planItem)
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:    planItem,
						IssuesFound: true,
						OutputErr:   outputErr,
					})
					logPolicyOutputItemError(l, outputErr)
					return
				}
			}
			if err != nil {
				outputErr = processIAMErrors(l, err, planItem)
				output = appendPolicyOutput(l, output, createPolicyOutputInput{
					PlanItem:    planItem,
					IssuesFound: true,
					OutputErr:   outputErr,
				})
				logPolicyOutputItemError(l, outputErr)
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
					// TODO: Output the affected items, e.g. access key ids
					output = appendPolicyOutput(l, output, createPolicyOutputInput{
						PlanItem:     planItem,
						ResourceName: *policy.PolicyName,
						ResourceArn:  *policy.Arn,
						IssuesFound:  issuesFound,
					})
				}
			}
		}
	} // end for policy
	if !anyFiltersMatch {
		output, err = processZeroMatches(l, processZeroMatchesInput{PlanItem: planItem})
	}
	return
}
