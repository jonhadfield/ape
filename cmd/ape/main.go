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

package main

import (
	"os"

	"github.com/RackSec/srslog"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"fmt"

	"reflect"

	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/jonhadfield/ape"
	h "github.com/jonhadfield/ape/helpers"
	"github.com/jonhadfield/ape/presets"
	r "github.com/jonhadfield/ape/root"
	golog "github.com/op/go-logging"
	"github.com/pkg/errors"
)

func getSysLogger(level string) (l *srslog.Writer, err error) {
	var priority srslog.Priority
	switch level {
	case "debug":
		priority = srslog.LOG_DEBUG
	case "info":
		priority = srslog.LOG_INFO
	case "warn":
		priority = srslog.LOG_WARNING
	case "error":
		priority = srslog.LOG_ERR
	case "critical":
		priority = srslog.LOG_CRIT
	}
	l, err = srslog.Dial("", "", priority, "ape")
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func processFileLogger(inLoggers []interface{}, filePath string) (outLoggers []interface{}, err error) {
	var file *os.File
	file, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	var fLogger = golog.MustGetLogger("example")
	fileBackend := golog.NewLogBackend(file, "", 0)
	var format = golog.MustStringFormatter(
		`%{time:2006-01-02T15:04:05-07:00} [%{level}] %{message}`,
	)

	fileBackendFormatter := golog.NewBackendFormatter(fileBackend, format)
	// Only errors and more severe messages should be sent to backend2
	fileBackendLeveled := golog.AddModuleLevel(fileBackendFormatter)

	switch strings.ToLower(*logLevel) {
	case "debug":
		fileBackendLeveled.SetLevel(golog.DEBUG, "")
	case "info":
		fileBackendLeveled.SetLevel(golog.INFO, "")
	case "notice":
		fileBackendLeveled.SetLevel(golog.NOTICE, "")
	case "warn":
		fileBackendLeveled.SetLevel(golog.WARNING, "")
	case "error":
		fileBackendLeveled.SetLevel(golog.ERROR, "")
	case "critical":
		fileBackendLeveled.SetLevel(golog.CRITICAL, "")
	}
	// Set the backends to be used and the default level.
	fLogger.SetBackend(fileBackendLeveled)
	if err == nil {
		outLoggers = append(inLoggers, fLogger)
	} else {
		h.OutputError(err)
		os.Exit(1)
	}
	return
}

var (
	playbookFilePathArg = kingpin.Arg("playbook", "playbook file path").Default("playbook.yml").String()
	accountsFilePathArg = kingpin.Flag("accounts", "accounts file path").String()
	policiesFilePathArg = kingpin.Flag("policies", "policies file path").String()
	regions             = kingpin.Flag("regions", "a single region or a comma separated list of regions to run against").Short('r').String()
	roleArn             = kingpin.Flag("role-arn", "arn of role to assume").String()
	externalID          = kingpin.Flag("external-id", "external id for role to assume").String()
	roleSessionName     = kingpin.Flag("role-session-name", "session name").String()
	stopOnError         = kingpin.Flag("stop-on-error", "stop on error").Bool()
	silent              = kingpin.Flag("silent", "suppress all output").Bool()
	logLevel            = kingpin.Flag("log-level", "debug, info, notice, warn, error, critical").Default("warn").String()
	logFile             = kingpin.Flag("log-file", "log to filepath").String()
	syslog              = kingpin.Flag("syslog", "log to syslog").Bool()
	verboseErrors       = kingpin.Flag("verbose-errors", "output class and line number with error messages").Bool()
	listSupported       = kingpin.Flag("list-supported", "list supported services and resources").Bool()
	output              = kingpin.Flag("output", "lines, table, or none").Default("lines").String()
	debug               = kingpin.Flag("debug", "enable: verbose-errors, stop-on-error, log-level=debug").Bool()
	listPresets         = kingpin.Flag("list-presets", "list available presets").Bool()
	generatePreset      = kingpin.Flag("generate-preset", "generate playbook and policies from presets-files").String()
	runPreset           = kingpin.Flag("run-preset", "run a preset").String()
	accessKeyID         = kingpin.Flag("access-key-id", "aws credential: access key id").String()
	secretAccessKey     = kingpin.Flag("secret-access-key", "aws credential: secret access key").String()
	sessionToken        = kingpin.Flag("session-token", "aws credential: session token").String()
)

var apeUsageTemplate = `{{define "FormatCommand"}}\
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}>{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}\
{{if .FlagSummary}} {{.FlagSummary}}{{end}}\
{{end}}\
{{define "FormatCommands"}}\
{{range .FlattenedCommands}}\
{{if not .Hidden}}\
  {{.FullCommand}}{{if .Default}}*{{end}}{{template "FormatCommand" .}}
{{.Help|Wrap 4}}
{{end}}\
{{end}}\
{{end}}\
{{define "FormatUsage"}}\
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}
{{if .Help}}
{{.Help|Wrap 0}}\
{{end}}\
{{end}}\
{{if .Context.SelectedCommand}}\
usage: {{.App.Name}} {{.Context.SelectedCommand}}{{template "FormatUsage" .Context.SelectedCommand}}
{{else}}\
usage: {{.App.Name}}{{template "FormatUsage" .App}}
{{end}}\
{{if .Context.Flags}}\
Flags:
{{.Context.Flags|FlagsToTwoColumns|FormatTwoColumns}}
{{end}}\
{{if .Context.Args}}\
Args:
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end}}\
{{if .Context.SelectedCommand}}\
{{if len .Context.SelectedCommand.Commands}}\
Subcommands:
{{template "FormatCommands" .Context.SelectedCommand}}
{{end}}\
{{else if .App.Commands}}\
Commands:
{{template "FormatCommands" .App}}
{{end}}\
`

// overwritten at build time
var version, versionOutput, tag, sha, buildDate string

func getPlaybookFilePath(path string) (result string, err error) {
	if _, fErr := os.Stat(path); !os.IsNotExist(fErr) {
		result = path
	} else {
		if path == "playbook.yml" {
			err = errors.New("playbook file not specified and default 'playbook.yml' not found")
			return
		}
		err = errors.Errorf("playbook file '%s' could not be found", path)
	}
	return
}

func mergePlaybookContent(allPlaybooksContent, tempPlaybook []byte) []byte {
	pbLines := strings.SplitAfter(string(tempPlaybook), "\n")
	for _, line := range pbLines {
		strippedLine := strings.Replace(line, " ", "", -1)
		if strippedLine == "" ||
			strings.Contains(strippedLine, "---") ||
			strings.Contains(strippedLine, "./policies.yml") ||
			strings.Contains(strippedLine, "plays:") ||
			strippedLine == "plays:" {
			continue
		} else {
			allPlaybooksContent = append(allPlaybooksContent, line...)
		}
	}
	return allPlaybooksContent
}

func processSpecifiedRegions(regions *string) (selectedRegions []string) {
	selectedRegions = strings.Split(*regions, ",")
	selectedRegions = h.Map(selectedRegions, strings.TrimSpace)
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	var allRegions = map[string]endpoints.Region{}
	for _, p := range partitions {
		pRegions := p.Regions()
		for k, v := range pRegions {
			allRegions[k] = v
		}
	}
	var invalidRegions []string
	for _, selectedRegion := range selectedRegions {
		if allRegions[selectedRegion] == (endpoints.Region{}) {
			invalidRegions = append(invalidRegions, selectedRegion)
		}
	}
	numInvalid := len(invalidRegions)
	regionOrRegions := "region"
	if numInvalid > 0 {
		if numInvalid > 1 {
			regionOrRegions = "regions"
		}
		h.OutputError(errors.Errorf("invalid %s specified: "+strings.Join(invalidRegions, ", "), regionOrRegions))
		os.Exit(1)
	}
	return
}

func mergePoliciesContent(allPoliciesContent, tempPolicies []byte) []byte {
	poLines := strings.SplitAfter(string(tempPolicies), "\n")
	for _, line := range poLines {
		strippedLine := strings.Replace(line, " ", "", -1)
		if strippedLine == "" ||
			strings.Contains(strippedLine, "---") ||
			strings.Contains(strippedLine, "policies:") {
			continue
		} else {
			allPoliciesContent = append(allPoliciesContent, line...)
		}
	}
	return allPoliciesContent
}

func main() {
	if tag != "" && buildDate != "" {
		versionOutput = fmt.Sprintf("[%s-%s] %s UTC", tag, sha, buildDate)
	} else {
		versionOutput = version
	}
	kingpin.Version(versionOutput)
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Parse()
	kingpin.UsageTemplate(apeUsageTemplate)
	var sysLogger *srslog.Writer
	var err error

	if *debug {
		*logLevel = "debug"
		*verboseErrors = true
		*stopOnError = true
	}

	if *listPresets {
		presets.List()
	}

	if *verboseErrors {
		r.VerboseErrors = true
	}

	var loggers []interface{}

	if *syslog {
		sysLogger, err = getSysLogger(*logLevel)
		if err != nil {
			err = errors.New("failed to get syslog logger")
			h.OutputError(err)
			os.Exit(1)
		}
		loggers = append(loggers, sysLogger)
	}

	if *generatePreset != "" {
		presets.Generate(loggers, *generatePreset)
	}

	if *logFile != "" {
		loggers, err = processFileLogger(loggers, *logFile)
		if err != nil {
			return
		}
	}

	if *listSupported {
		ape.ListSupported()
		os.Exit(0)
	}

	if *stopOnError {
		r.StopOnError = true
	}

	var selectedRegions []string
	if *regions != "" {
		selectedRegions = processSpecifiedRegions(regions)
	}

	args := r.CommandLineArgs{
		RoleArn:          *roleArn,
		ExternalID:       *externalID,
		RoleSessionName:  *roleSessionName,
		AccountsFilePath: *accountsFilePathArg,
		PoliciesFilePath: *policiesFilePathArg,
		StopOnError:      *stopOnError,
		LogLevel:         *logLevel,
		Output:           *output,
		Regions:          selectedRegions,
		AccessKeyID:      *accessKeyID,
		SecretAccessKey:  *secretAccessKey,
		SessionToken:     *sessionToken,
	}

	var config r.Configs
	// load from preset if specified
	if *runPreset != "" {
		var playbookFileContent, policiesFileContent []byte
		// are multiple specified?
		if strings.Contains(*runPreset, ",") {
			presetNames := strings.Split(*runPreset, ",")
			// get the first lot and then append the rest with their header text stripped
			var allPlaybooksContent, allPoliciesContent []byte
			for i, presetName := range presetNames {
				if i == 0 {
					allPlaybooksContent, allPoliciesContent = presets.Load(loggers, presetName)
				} else {
					// strip headers for playbook and policies
					tempPlaybook, tempPolicies := presets.Load(loggers, presetName)

					allPlaybooksContent = mergePlaybookContent(allPlaybooksContent, tempPlaybook)

					allPoliciesContent = mergePoliciesContent(allPoliciesContent, tempPolicies)

				}
				playbookFileContent = allPlaybooksContent
				policiesFileContent = allPoliciesContent

			}
		} else {
			playbookFileContent, policiesFileContent = presets.Load(loggers, *runPreset)
		}

		if len(playbookFileContent) > 0 {
			config.Playbook, err = ape.ParsePlaybookFileContent(playbookFileContent)
			if err != nil {
				h.OutputError(err)
				os.Exit(1)
			}
		}
		if len(policiesFileContent) > 0 {
			config.Policies, err = ape.ParsePoliciesFileContent(policiesFileContent)
			if err != nil {
				h.OutputError(err)
				os.Exit(1)
			}
		}
	} else {
		// load from filesystem
		var playbookFilePath string
		playbookFilePath, err = getPlaybookFilePath(*playbookFilePathArg)
		if err != nil {
			h.OutputError(err)
			os.Exit(1)
		}

		config, err = ape.LoadConfigs(loggers, ape.LoadConfigsInput{
			PlaybookFilePath: playbookFilePath,
			PoliciesFilePath: args.PoliciesFilePath,
			AccountsFilePath: args.AccountsFilePath,
			Args:             args,
		})
		if err != nil {
			h.OutputError(err)
			os.Exit(1)
			return
		}
	}

	var createPlanOutput ape.CreatePlanOutput
	createPlanOutput, err = ape.CreatePlan(loggers, &ape.CreatePlanInput{
		Playbook:   config.Playbook,
		Accounts:   config.Accounts,
		Policies:   config.Policies,
		Args:       args,
		OutputFile: "",
	})

	if err != nil {
		h.OutputError(err)
		os.Exit(1)
	}

	if *silent {
		var emailDefined, slackDefined bool
		if !reflect.DeepEqual(createPlanOutput.Email, r.Email{}) {
			emailDefined = true
		}
		if !reflect.DeepEqual(createPlanOutput.Slack, r.Slack{}) {
			slackDefined = true
		}
		if !emailDefined && !slackDefined {
			message := "no output methods defined"
			h.Error(loggers, message)
			h.OutputError(errors.New(message))
			os.Exit(1)
		}
		// disable output
		args.Output = ""
	}

	enforceInput := &ape.EnforcePlanInput{
		Args:  args,
		Email: createPlanOutput.Email,
		Slack: createPlanOutput.Slack,
	}
	plan := createPlanOutput.Plan
	if len(*plan) > 0 {
		var failures bool
		failures, err = plan.Enforce(loggers, *enforceInput)
		if err != nil {
			if awsErr, okBPA2 := errors.Cause(err).(awserr.Error); okBPA2 {
				if awsErr.Code() == "AccessDenied" && strings.Contains(awsErr.Message(), "sts:AssumeRole") {
					// don't ignore assume role errors
					h.OutputError(err)
					os.Exit(1)
				}
			}
			if r.StopOnError {
				h.OutputError(err)
				os.Exit(1)
			}
		}

		// if user ignored failures, but there were errors, then exit with 1
		if failures {
			os.Exit(1)
		}
	} else {
		err = fmt.Errorf("no plays defined")
		h.OutputError(err)
		os.Exit(1)
	}

}
