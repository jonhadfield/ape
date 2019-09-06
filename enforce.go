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

	"time"

	"reflect"

	"github.com/fatih/color"

	"sort"

	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

type EnforcePlanInput struct {
	RoleArn         string
	ExternalID      string
	RoleSessionName string
	Args            r.CommandLineArgs
	Email           r.Email
	Slack           r.Slack
}

type createPolicyOutputInput struct {
	PlanItem     PlanItem
	Details      []enforcePolicyOutputItemDetail
	Severity     string // for overriding plan
	Message      string
	Action       string
	ActionResult string
	IssuesFound  bool
	ResourceName string
	ResourceArn  string
	Region       string
	OutputErr    policyItemOutputError
}

type processZeroMatchesInput struct {
	Message      string
	Action       string
	ActionResult string
	PlanItem     PlanItem
}

type policyItemOutputError struct {
	level   string
	error   error
	message string
}

func processZeroMatches(l []interface{}, input processZeroMatchesInput) (output enforcePolicyOutput, err error) {
	var issuesFound bool
	if input.PlanItem.Policy.ModifyResult != "" {
		if input.PlanItem.Policy.ModifyResult == "reverse" {
			issuesFound = true
		} else {
			err = errors.Errorf("unknown result modifier: %s", input.PlanItem.Policy.ModifyResult)
			if err != nil {
				return
			}
		}
	}
	output = appendPolicyOutput(l, output, createPolicyOutputInput{
		PlanItem:    input.PlanItem,
		Message:     input.Message,
		IssuesFound: issuesFound,
	})
	return
}

func appendPolicyOutput(l []interface{}, existing enforcePolicyOutput,
	input createPolicyOutputInput) (output enforcePolicyOutput) {
	h.Debug(l, "appending policy output")

	var playName string
	if input.PlanItem.Play != nil && input.PlanItem.Play.Name != "" {
		playName = input.PlanItem.Play.Name
	}

	output = append(existing, enforcePolicyOutputItem{
		PlayName:     playName,
		AccountID:    input.PlanItem.Target.AccountID,
		AccountAlias: input.PlanItem.Target.AccountAlias,
		PolicyName:   input.PlanItem.Policy.Name,
		Region:       input.Region,
		ResourceName: input.ResourceName,
		ResourceArn:  input.ResourceArn,
		Severity:     input.PlanItem.Policy.Severity,
		Message:      input.Message,
		Details:      input.Details,
		IssuesFound:  input.IssuesFound,
		Time:         time.Now(),
		OutputErr:    input.OutputErr,
	})
	return
}

type enforcePlanOutput []enforcePlanItemOutput

type enforcePlanItemInput struct {
	session *session.Session
}

type enforcePlanItemOutput []enforcePolicyOutput

type enforcePolicyOutputItemDetail struct {
	ResourceID     string
	ResourceName   string
	ResourceType   string
	ResourceArn    string
	MatchingPolicy *r.Policy
}

type enforcePolicyOutputItem struct {
	AccountID    string
	AccountAlias string
	PlayName     string
	PolicyName   string
	Region       string
	ResourceName string
	ResourceType string
	ResourceArn  string
	Message      string
	Action       string
	ActionResult string
	Severity     string // critical, high, medium, low, info
	Details      []enforcePolicyOutputItemDetail
	IssuesFound  bool
	Time         time.Time
	OutputErr    policyItemOutputError
}

type enforcePolicyOutput []enforcePolicyOutputItem

type issuesSummary struct {
	Critical         int
	High             int
	Medium           int
	Low              int
	Info             int
	Total            int
	Highest          int64
	HighestByAccount map[string]string
}

func getHigherSeverity(one, two string) string {
	if severities[one] >= severities[two] {
		return one
	}
	return two
}

func getIssuesSummary(enforcePlanOutput enforcePlanOutput) (summary issuesSummary) {
	for _, planItemOutput := range enforcePlanOutput {
		for _, policyOutput := range planItemOutput {
			for i := range policyOutput {
				policyOutputItem := policyOutput[i]
				if !reflect.DeepEqual(policyOutputItem, enforcePolicyOutputItem{}) {
					if policyOutputItem.IssuesFound {
						switch strings.ToLower(policyOutputItem.Severity) {
						case "critical":
							summary.Critical++
						case "high":
							summary.High++
						case "medium":
							summary.Medium++
						case "low":
							summary.Low++
						case "info":
							summary.Info++
						}
						if summary.HighestByAccount == nil {
							summary.HighestByAccount = make(map[string]string)
						}
						if summary.HighestByAccount[policyOutputItem.AccountAlias] != "" {
							summary.HighestByAccount[policyOutputItem.AccountAlias] =
								getHigherSeverity(summary.HighestByAccount[policyOutputItem.AccountAlias],
									strings.ToLower(policyOutputItem.Severity))
						} else {
							summary.HighestByAccount[policyOutputItem.AccountAlias] =
								strings.ToLower(policyOutputItem.Severity)

						}

					}
				}
			}
		}
	}
	summary.Total = summary.Critical + summary.High + summary.Medium + summary.Low + summary.Info

	if summary.Critical > 0 {
		summary.Highest = severities["critical"]
	} else if summary.High > 0 {
		summary.Highest = severities["high"]
	} else if summary.Medium > 0 {
		summary.Highest = severities["medium"]
	} else if summary.Low > 0 {
		summary.Highest = severities["low"]
	} else if summary.Info > 0 {
		summary.Highest = severities["info"]
	}
	return
}

func (pi PlanItem) enforce(l []interface{}, input enforcePlanItemInput) (output enforcePlanItemOutput, err error) {
	colonPos := strings.Index(pi.Policy.Resource, ":")
	if colonPos < 2 {
		err = fmt.Errorf("missing colon or invalid resource: %s", pi.Policy.Resource)
		err = errors.WithStack(err)
		return
	}
	var service string
	service, _, err = h.GetResourceParts(pi.Policy.Resource)
	if err != nil {
		return
	}
	var ePO enforcePolicyOutput
	switch service {
	case "iam":
		ePO, err = enforceIAMPolicy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	case "ec2":
		ePO, err = enforceEC2Policy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	case "cloudtrail":
		ePO, err = enforceCloudTrailPolicy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	case "config":
		ePO, err = enforceConfigPolicy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	case "s3":
		ePO, err = enforceS3Policy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	case "kms":
		ePO, err = enforceKmsPolicy(l, input.session, pi)
		output = append(output, ePO)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("unknown service: %s", pi.Policy.Resource)
		return
	}
	return
}

func getAccountID(l []interface{}, sess *session.Session) (id string) {
	h.Debug(l, "getting account id using sts")
	stsSvc := sts.New(sess)
	callerID, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	credsNotFoundMessage := "credentials not found\nsee: https://docs.aws.amazon.com/cli/" +
		"latest/userguide/cli-chap-getting-started.html#cli-quick-configuration"
	if err != nil {
		if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
			if strings.Contains(awsErr.Message(), "non-User credentials") {
				// not using user creds, so need to try a different method
				h.Info(l, "using non-user credentials")
			} else if awsErr.Code() == "NoCredentialProviders" {
				err = errors.New(credsNotFoundMessage)
				h.Error(l, credsNotFoundMessage)
				h.OutputError(err)
				os.Exit(1)
			} else if awsErr.Code() == "ExpiredToken" {
				err = errors.New("temporary credentials have expired")
				h.Error(l, "temporary credentials have expired")
				h.OutputError(err)
				os.Exit(1)
			} else if strings.Contains(awsErr.Message(), "security token included in the request is invalid") {
				err = errors.New("specified credentials have an invalid security token")
				h.Error(l, "specified credentials have an invalid security token")
				h.OutputError(err)
				os.Exit(1)

			} else {
				h.Error(l, fmt.Sprintf("unhandled exception using specified credentials: %s", awsErr.Message()))
			}
		}
	} else if callerID.Arn == nil {
		err = errors.New("credentials not found\nsee: https://docs.aws.amazon.com/cli/" +
			"latest/userguide/cli-chap-getting-started.html#cli-quick-configuration")
		h.OutputError(err)
		os.Exit(1)
	} else {
		id = *callerID.Account
		return
	}

	return
}

func getAccountAlias(l []interface{}, sess *session.Session) (alias string) {
	// try to get the account alias
	h.Debug(l, "trying to discover account alias")
	iamSvc := iam.New(sess)
	var getAliasOutput *iam.ListAccountAliasesOutput
	var err error
	getAliasOutput, err = iamSvc.ListAccountAliases(&iam.ListAccountAliasesInput{})
	if err != nil {
		h.Debug(l, "missing \"iam:ListAccountAliases\" permission so unable to retrieve alias")
	} else if len(getAliasOutput.AccountAliases) > 0 {
		alias = *getAliasOutput.AccountAliases[0]
	}
	return
}

func (p plan) Enforce(l []interface{}, input EnforcePlanInput) (failures bool, err error) {
	var planOutput enforcePlanOutput
	var initialSess *session.Session
	var staticCreds *credentials.Credentials
	if input.Args.AccessKeyID != "" && input.Args.SecretAccessKey != "" {
		// use credentials specified on command line
		staticCreds = credentials.NewStaticCredentials(input.Args.AccessKeyID,
			input.Args.SecretAccessKey, input.Args.SessionToken)
		initialSess, err = session.NewSession(&aws.Config{Credentials: staticCreds})
	} else {
		// try discovering credentials
		initialSess, err = session.NewSession()
	}
	if err != nil {
		h.OutputError(err)
		os.Exit(1)
	}

	var accountID, accountAlias string
	// if a role is in the plan, then we're assuming credentials
	if input.RoleArn != "" {
		initialCreds, getInitialCredsErr := h.GetAssumeRoleCreds(h.GetAssumeRoleCredsInput{
			Sess:       initialSess,
			RoleArn:    input.RoleArn,
			ExternalID: input.ExternalID,
		})
		if getInitialCredsErr != nil {
			err = errors.WithStack(getInitialCredsErr)
			return
		}
		initialSess, err = session.NewSession(&aws.Config{Credentials: initialCreds})
		if err != nil {
			return
		}
	}
	// if no account id is specified, then we're just dealing with a single account,
	// relating to the discovered credentials
	if p[0].Target.AccountID == "" && input.Args.Output != "" {
		accountID = getAccountID(l, initialSess)
		accountAlias = getAccountAlias(l, initialSess)
		accountDisplay := fmt.Sprintf("\n ACCOUNT: %s (%s)\n\n", accountID, accountAlias)
		// white := color.New(color.FgHiWhite).SprintFunc()
		fmt.Print(color.New(color.FgHiWhite).SprintFunc()(accountDisplay))
	}

	// Sort accounts by name
	sort.SliceStable(p, func(i, j int) bool { return p[i].Target.AccountAlias < p[j].Target.AccountAlias })

	// Order plan by service?
	var lastAccountID string
	var reportAccount bool
	var newSess *session.Session
	// Loop through plan
	for i := range p {
		planItem := p[i]
		// if account id is specified then we're using multiple accounts and know credentials will be assumed
		if planItem.Target.AccountID != "" {
			// if plan item is for same account as before, then reuse, otherwise clear caches and assume new role
			if planItem.Target.AccountID != lastAccountID {
				reportAccount = true
				lastAccountID = planItem.Target.AccountID
				creds, getCredsErr := h.GetAssumeRoleCreds(h.GetAssumeRoleCredsInput{
					Sess:       initialSess,
					AccountID:  planItem.Target.AccountID,
					RoleName:   planItem.Target.Role,
					ExternalID: planItem.Target.ExternalID,
				})
				if getCredsErr != nil {

					return true, errors.WithMessage(getCredsErr,
						fmt.Sprintf("role arn: %s", planItem.Target.Role))
				}
				var newSessionErr error
				newSess, newSessionErr = session.NewSession(&aws.Config{Credentials: creds})
				if newSessionErr != nil {
					return true, newSessionErr
				}
				accountID = getAccountID(l, newSess)
				accountAlias = getAccountAlias(l, newSess)
			} else {
				reportAccount = false
			}
		} else {
			// reuse existing session as it's a single account
			newSess = initialSess
			planItem.Target.AccountID = accountID
			planItem.Target.AccountAlias = accountAlias
		}
		if input.Args.Output != "" {
			var shortAccountOutput string
			if accountAlias != "" {
				shortAccountOutput = accountAlias
			} else {
				shortAccountOutput = accountID
			}
			statusOutput := fmt.Sprintf("Processing: [%s] %s...", shortAccountOutput, planItem.Policy.Name)
			statusOutput = h.PadToWidth(statusOutput, " ", 0, true)
			width, _, _ := terminal.GetSize(0)
			if len(statusOutput) == width {
				fmt.Printf(statusOutput[0:width-3] + "   \r")
			} else {
				fmt.Print(statusOutput)
			}
		}

		execPlanItemInput := enforcePlanItemInput{
			session: newSess,
		}
		var planItemOutput enforcePlanItemOutput
		planItemOutput, err = planItem.enforce(l, execPlanItemInput)
		// Build a list of output to display after processing has completed
		planOutput = append(planOutput, planItemOutput)
		if input.Args.Output == "lines" {
			// Report each item as it's processed
			reportItem(planItemOutput, reportAccount)
		}

		if err != nil {
			h.Error(l, err.Error())
			if r.StopOnError {
				return true, err
			}
		}
	}
	err = complete(l, initialSess, planOutput, input)
	return
}

func complete(l []interface{},
	session *session.Session, planOutput enforcePlanOutput, input EnforcePlanInput) (err error) {
	// Clear console
	fmt.Printf("%s", h.PadToWidth("", " ", 0, false))

	// Print to table
	if input.Args.Output == "table" {
		err = planOutput.printToMDTable(l)
	}
	if err != nil {
		return
	}

	summary := getIssuesSummary(planOutput)

	if summary.Total == 0 {
		h.Notice(l, "no issues found")
	} else {
		h.Notice(l, fmt.Sprintf("%d issues found", summary.Total))
	}

	if emailConfigDefined(input.Email) {
		h.Debug(l, fmt.Sprintf("email threshold: %s (%d) summary highest: %d\n",
			input.Email.Threshold, severities[strings.ToLower(input.Email.Threshold)], summary.Highest))

		if input.Email.Threshold == "" || severities[strings.ToLower(input.Email.Threshold)] <= summary.Highest {
			h.Notice(l, "sending email")
			// set default threshold on email to low if not defined

			err = planOutput.emailResults(l, session, input.Email, summary)
			if err != nil {
				return
			}
		}

	} else {
		h.Notice(l, "email configuration not provided, so unable to send")
	}

	if slackConfigDefined(input.Slack) {
		h.Notice(l, "posting summary to slack")
		// set default threshold on slack to low if not defined
		if input.Slack.Threshold == "" {
			input.Slack.Threshold = "low"
		}
		err = planOutput.postResultsToSlack(l, input.Slack)
		if err != nil {
			if strings.Contains(err.Error(), "Slack server error") {
				h.OutputError(errors.New("failed to post to Slack as it appears to be down"))
			} else {
				return
			}
		}
	} else {
		h.Notice(l, "slack configuration not provided, so unable to send")
	}

	return

}

// enforcePlanOutput <- enforcePlanOutputItems <- enforcePolicyOutput <- enforcePolicyOutputItem
