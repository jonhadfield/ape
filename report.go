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
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"crypto/tls"
	"strconv"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/fatih/color"
	h "github.com/jonhadfield/ape/helpers"
	r "github.com/jonhadfield/ape/root"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"gopkg.in/gomail.v2"
)

func ListSupported() {
	var lastService string
	var serviceOut string
	var lastResource string
	var resourceOut string
	var data [][]string
	for _, impService := range h.ImplementedServices {
		for _, resource := range impService.Resources {
			for _, criteria := range resource.Criteria {

				if lastService != impService.Name {
					serviceOut = impService.Name
					lastService = impService.Name
				} else {
					serviceOut = ""
				}

				if lastResource != resource.Name {
					resourceOut = resource.Name
					lastResource = resource.Name
				} else {
					resourceOut = ""
				}

				row := []string{serviceOut, resourceOut, criteria.Name, strings.Join(criteria.Units, ", "), strings.Join(criteria.Comparisons, ", ")}
				data = append(data, row)
			}
		}
	}
	if len(data) > 0 {
		fmt.Println()
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "Resource", "Criteria", "Units", "Comparisons"})
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
		table.AppendBulk(data) // Add Bulk Data
		table.Render()
	}
}

func (epoi enforcePolicyOutputItem) createReportLine() (output string) {
	if epoi.OutputErr.message != "" {
		// if we had an error, then we're done
		output = epoi.OutputErr.message
	} else if epoi.ResourceArn != "" && epoi.ResourceName != "" {
		// if arn and name
		output = fmt.Sprintf("%s | %s", epoi.ResourceName, epoi.ResourceArn)
	} else if epoi.ResourceName != "" {
		// if just name
		output = epoi.ResourceName
	} else if epoi.ResourceArn != "" {
		// if just arn
		output = epoi.ResourceArn
	}

	// if we got a region, then append
	if epoi.Region != "" {
		output = fmt.Sprintf("%s (%s)", output, epoi.Region)
	}

	// if a message was passed and we're not outputting an error
	if epoi.Message != "" && epoi.OutputErr.message == "" {
		// append to existing input
		if output != "" {
			output = output + "\n" + epoi.Message
		} else {
			// if no existing output, then just output message
			output = epoi.Message
		}
	}
	return
}

func getSeverity(input *enforcePolicyOutputItem) (severity string, err error) {
	redBold := color.New(color.FgRed).Add(color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	white := color.New(color.FgHiWhite).SprintFunc()
	if !input.IssuesFound {
		severity = green("OK")
	} else {
		switch input.Severity {
		case "critical":
			severity = redBold(strings.ToUpper(input.Severity))
		case "high":
			severity = red(strings.ToUpper(input.Severity))
		case "medium":
			severity = yellow(strings.ToUpper(input.Severity))
		case "low":
			severity = cyan(strings.ToUpper(input.Severity))
		case "info":
			severity = white(strings.ToUpper(input.Severity))
		default:
			err = errors.Errorf("invalid severity: '%s'", severity)
		}
	}
	return
}

func (po enforcePlanOutput) printToMDTable(l []interface{}) (err error) {
	h.Debug(l, "printing console table report")
	var data [][]string

	var moreThanOneAccount bool
	var lastAccountID string
	// Check if single account or multiple
	for i := range po {
		planItem := po[i]
		for _, ePO := range planItem {
			for j := range ePO {
				ePOI := ePO[j]
				if lastAccountID != "" && ePOI.AccountID != lastAccountID {
					moreThanOneAccount = true
					goto OUTPUT
				}
				lastAccountID = ePOI.AccountID
			}
		}
	}
OUTPUT:
	var lastItem = map[string]string{}
	if !moreThanOneAccount {
		for _, planItem := range po {
			for _, ePO := range planItem {
				for _, ePOI := range ePO {
					var severity string
					severity, err = getSeverity(&ePOI)
					output := ePOI.createReportLine()

					var row []string
					if ePOI.PolicyName == lastItem["policyName"] && ePOI.AccountID == lastItem["accountID"] {
						row = []string{"", "", output}
					} else {
						row = []string{severity, ePOI.PlayName + " - " + ePOI.PolicyName, output}
					}
					lastItem["policyName"] = ePOI.PolicyName
					lastItem["accountID"] = ePOI.AccountID

					data = append(data, row)
				}
			}
		}
	} else {
		for _, planItem := range po {
			for _, ePO := range planItem {
				for _, ePOI := range ePO {
					accountOutput := fmt.Sprintf("%s (%s)", ePOI.AccountID, ePOI.AccountAlias)
					var severity string
					severity, err = getSeverity(&ePOI)
					output := ePOI.createReportLine()
					row := []string{severity, accountOutput, ePOI.PlayName + " - " + ePOI.PolicyName, output}
					data = append(data, row)
				}
			}
		}
	}

	if len(data) > 0 {
		table := tablewriter.NewWriter(os.Stdout)
		if moreThanOneAccount {
			table.SetHeader([]string{"Severity", "Account (alias)", "Policy", "Resource"})
		} else {
			table.SetHeader([]string{"Severity", "Policy", "Resource"})

		}

		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
		table.AppendBulk(data) // Add Bulk Data
		table.Render()
	}
	return
}

type dataRow struct {
	result       string
	accountID    string
	accountAlias string
	policyName   string
	resource     string
}

func (po enforcePlanOutput) generateXLSXData(l []interface{}) (data []dataRow) {
	h.Debug(l, "generating XLSX data")
	for _, planItem := range po {
		for _, ePO := range planItem {
			for _, ePOItem := range ePO {
				var result string
				if !ePOItem.IssuesFound {
					result = "OK"
				} else {
					result = strings.ToUpper(ePOItem.Severity)
				}
				output := ePOItem.createReportLine()
				var aliasOutput = ePOItem.AccountAlias
				if aliasOutput == "" {
					aliasOutput = "-"
				}
				row := dataRow{
					result:       result,
					accountID:    ePOItem.AccountID,
					accountAlias: aliasOutput,
					policyName:   ePOItem.PlayName + " - " + ePOItem.PolicyName,
					resource:     output,
				}
				data = append(data, row)
			}
		}
	}
	return
}

func (po enforcePlanOutput) generateXLSX(l []interface{}) (filePath string, err error) {
	h.Debug(l, "generating XLSX")
	var sheetName string
	var data = po.generateXLSXData(l)
	if len(data) > 0 {
		xlsx := excelize.NewFile()
		var headerStyle, standardOutputStyle, criticalResultStyle, highResultStyle, mediumResultStyle, lowResultStyle, infoResultStyle, okResultStyle int

		headerStyle, _ = xlsx.NewStyle(`{"fill":{"type":"pattern","color":["#000066"],"pattern":1},"font":{"bold":true,"italic":false,"family":"Calibri","size":14,"color":"#f2f2f2"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		criticalResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#ff0000"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		highResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#cc0000"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		mediumResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#cc6600"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		lowResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#003399"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		infoResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#000000"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		okResultStyle, _ = xlsx.NewStyle(`{"font":{"bold":true,"italic":false,"family":"Calibri","size":12,"color":"#005A00"},"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":false}}`)
		standardOutputStyle, _ = xlsx.NewStyle(`{"font":{"bold":false,"italic":false,"family":"Calibri","size":12,"color":"#000000"},"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"vertical":"","wrap_text":true}}`)

		var lastAccount string
		var lastPolicyName string
		var rowNo int
		for count, outRow := range data {
			sheetName = outRow.accountAlias
			var newSheet bool
			if count == 0 {
				xlsx.SetSheetName(xlsx.GetSheetName(1), sheetName)
				newSheet = true
			} else if outRow.accountID != lastAccount {
				// set styling on current sheet before creating new
				// xlsx.SetCellStyle(lastSheetName, "A2", "A"+strconv.Itoa(count+2), criticalResultStyle)
				newSheet = true
				// Create a new sheet.
				_ = xlsx.NewSheet(sheetName)
			}
			if newSheet {
				// reset row number
				rowNo = 0
				xlsx.SetCellValue(sheetName, "A1", "RESULT")
				xlsx.SetCellValue(sheetName, "B1", "POLICY")
				xlsx.SetCellValue(sheetName, "C1", "RESOURCE")
				xlsx.SetCellStyle(sheetName, "A1", "C1", headerStyle)
				xlsx.SetColWidth(sheetName, "A", "A", 20)
				xlsx.SetColWidth(sheetName, "B", "C", 70)
			}

			lastAccount = outRow.accountID
			var policyName string
			// Only set policyName if it's different to the last
			result := outRow.result
			if outRow.policyName != lastPolicyName {
				policyName = outRow.policyName
				lastPolicyName = outRow.policyName
			} else {
				policyName = ""
				result = ""
			}
			row := strconv.Itoa(rowNo + 2)
			resultCell := "A" + row
			policyCell := "B" + row
			resourceCell := "C" + row
			xlsx.SetCellValue(sheetName, resultCell, result)
			switch result {
			case "CRITICAL":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, criticalResultStyle)
			case "HIGH":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, highResultStyle)
			case "MEDIUM":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, mediumResultStyle)
			case "LOW":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, lowResultStyle)
			case "INFO":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, infoResultStyle)
			case "OK":
				xlsx.SetCellStyle(sheetName, "A"+row, "A"+row, okResultStyle)

			}
			xlsx.SetCellValue(sheetName, policyCell, policyName)
			xlsx.SetCellValue(sheetName, resourceCell, outRow.resource)
			xlsx.SetCellStyle(sheetName, "B"+row, "C"+row, standardOutputStyle)
			rowNo = rowNo + 1
		}

		timeStamp := time.Now().UTC().Format("20060102150405")
		filePath = fmt.Sprintf("ape_report_%s.xlsx", timeStamp)
		err = xlsx.SaveAs(filePath)
		if err != nil {
			return
		}
	}
	return
}

func (po enforcePlanOutput) postResultsToSlack(l []interface{}, slack r.Slack) (err error) {
	h.Debug(l, "posting results to slack")
	err = validateSlackSettings(slack)
	if err != nil {
		return
	}
	var ItemID, lastItemID string
	var slackText []string
	for _, planItem := range po {
		for _, ePO := range planItem {
			var lastItem, finalItem enforcePolicyOutputItem
			var printFinal bool
			for count, enforcePOItem := range ePO {
				if enforcePOItem.IssuesFound && severities[enforcePOItem.Severity] >= severities[slack.Threshold] {
					ItemID = enforcePOItem.PolicyName + enforcePOItem.AccountID
					lastItemID = lastItem.PolicyName + lastItem.AccountID

					slackTextOutput := enforcePOItem.createReportLine()

					// if it's the first, but not the only item, then append the text output and move on to the next one
					if count == 0 {
						slackText = append(slackText, slackTextOutput)
						lastItem = enforcePOItem
						finalItem = lastItem
						printFinal = true
						continue
					}
					// if it's the same as the last one and it's not the last, then append to text and move on to the next one
					if ItemID == lastItemID {
						slackText = append(slackText, slackTextOutput)
						lastItem = enforcePOItem
						finalItem = lastItem
						printFinal = true
						continue
					}
					// if this is a different item and not final, then output last, and then set last to be this one
					if ItemID != lastItemID {
						slackText = append(slackText, slackTextOutput)
						err = printo(slack, lastItem, slackText)
						if err != nil {
							return err
						}
						lastItem = enforcePOItem
						slackText = nil
						printFinal = false
					}
				}
			}
			if printFinal {
				// print last item, and then continue
				err = printo(slack, finalItem, slackText)
				if err != nil {
					return
				}
				slackText = nil
			}
		}
	}
	return
}

func printo(slackConfig r.Slack, item enforcePolicyOutputItem, slackText []string) (err error) {
	// print last item, and then continue
	var colour string
	switch item.Severity {
	case "critical":
		colour = "#ff0000"
	case "high":
		colour = "#FF4500"
	case "medium":
		colour = "#FF8C00"
	case "low":
		colour = "#0000ff"
	}
	messageInput := h.PostSlackMessageInput{
		Color:   colour,
		PreText: fmt.Sprintf("%s | %s - %s", strings.ToUpper(item.Severity), item.PlayName, item.PolicyName),
		Title:   fmt.Sprintf("account: %s (%s)", item.AccountAlias, item.AccountID),
		Text:    slackText,
	}
	err = h.PostSlackMessage(slackConfig, messageInput)
	return
}

func (po enforcePlanOutput) emailResults(l []interface{}, sess *session.Session, email r.Email, summary issuesSummary) (err error) {
	err = validateEmailSettings(email)
	if err != nil {
		return
	}
	var filePath string
	filePath, err = po.generateXLSX(l)
	if err != nil {
		return
	}

	msg := gomail.NewMessage()
	msg.SetHeader("From", email.Source)
	var emailSubject string
	if email.Subject != "" {
		emailSubject = email.Subject
	} else {
		emailSubject = "AWS Account Scan"
	}

	if summary.Critical > 0 {
		emailSubject += " - Critical issues found"
	} else if summary.High > 0 {
		emailSubject += " - High severity issues found"
	} else if summary.Medium > 0 {
		emailSubject += " - Medium severity issues found"
	}
	msg.SetHeader("Subject", emailSubject)

	body := "<font face=\"Courier New, Courier, monospace\">" +
		"&nbsp;FINDINGS<br/>" +
		"----------" +
		"<br/>" +
		"</font>" +
		"<table border=\"0\" cellpadding=\"3\" cellspacing=\"3\" width=\"100\">" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">CRITICAL</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(summary.Critical) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">HIGH</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(summary.High) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">MEDIUM</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(summary.Medium) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">LOW</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(summary.Low) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">INFO</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(summary.Info) + "</font></td>" +
		"</tr>" +
		"</table>" +

		"<br/><font face=\"Courier New, Courier, monospace\">" +
		"&nbsp;HIGHEST BY ACCOUNT<br/>" +
		"--------------------" +
		"<br/>" +
		"</font>" +
		"<table border=\"0\" cellpadding=\"3\" cellspacing=\"4\" width=\"300\">"

	for acc, sev := range summary.HighestByAccount {
		body += "<tr><td width=\"200\"><font face=\"Courier New, Courier, monospace\">" + acc + "</font></td>" +
			"<td width=\"100\"><font face=\"Courier New, Courier, monospace\">" + strings.ToUpper(sev) + "</font></td></tr>"

	}
	// close table
	body = body + "</table>"
	// TODO: ADD LIST OF CRITICAL AND HIGH POLICY NAMES
	msg.SetBody("text/html", body)
	msg.Attach(filePath)

	var emailRaw bytes.Buffer
	_, err = msg.WriteTo(&emailRaw)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	switch email.Provider {
	case "ses":
		msg.SetHeader("To", strings.Join(email.Recipients, ","))
		svc := ses.New(sess, &aws.Config{Region: h.PtrToStr(email.Region)})
		message := ses.RawMessage{Data: emailRaw.Bytes()}
		source := aws.String(email.Source)
		var destinations []*string
		for _, dest := range email.Recipients {
			destinations = append(destinations, h.PtrToStr(dest))
		}
		input := ses.SendRawEmailInput{Source: source, Destinations: destinations, RawMessage: &message}
		_, err = svc.SendRawEmail(&input)
		if err != nil {
			delErr := h.DeleteFile(filePath)
			if delErr != nil {
				err = errors.WithStack(delErr)
				return
			}
			return
		}

	case "smtp":
		msg.SetHeader("To", email.Recipients...)
		host := email.Host
		port, _ := strconv.Atoi(email.Port)
		dialer := gomail.NewPlainDialer(host, port, email.Username, email.Password)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		}
		dialer.TLSConfig = tlsConfig
		err = dialer.DialAndSend(msg)
		if err != nil {
			delErr := h.DeleteFile(filePath)
			if delErr != nil {
				err = errors.WithStack(delErr)
				return
			}
			return
		}
	}
	err = h.DeleteFile(filePath)
	return
}

func reportItem(item enforcePlanItemOutput, reportAccount bool) {
	redBold := color.New(color.FgRed).Add(color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	white := color.New(color.FgHiWhite).SprintFunc()
	if reportAccount {
		accLine := white(fmt.Sprintf(" ACCOUNT: %s (%s)", item[0][0].AccountID, item[0][0].AccountAlias))
		fmt.Println(h.PadToWidth("", " ", 0, false))
		fmt.Println(h.PadToWidth(accLine, " ", 0, false))
		fmt.Println(h.PadToWidth("", " ", 0, false))
	}

	var lastPolicyName string
	for _, ePO := range item {
		for i := range ePO {
			ePOItem := ePO[i]
			var justAffectedResource bool
			if (ePOItem.ResourceArn != "" || ePOItem.Message != "") && !ePOItem.IssuesFound && ePOItem.PolicyName == lastPolicyName {
				justAffectedResource = true
			} else if (ePOItem.ResourceName != "" || ePOItem.ResourceArn != "" || ePOItem.Message != "") && ePOItem.IssuesFound && ePOItem.PolicyName == lastPolicyName {
				// if it's got a resource ARN, message, issues were found and policyname is the same, then it's just a resource to output
				justAffectedResource = true
			} else if ePOItem.PolicyName == lastPolicyName && ePOItem.OutputErr.error != nil {
				justAffectedResource = true
			}
			lastPolicyName = ePOItem.PolicyName
			var spaceAfter int
			var severity string
			if !ePOItem.IssuesFound {
				severity = green("OK")
			} else {
				switch ePOItem.Severity {
				case "critical":
					severity = redBold(strings.ToUpper(ePOItem.Severity))
					spaceAfter = 1
				case "high":
					severity = red(strings.ToUpper(ePOItem.Severity))
					spaceAfter = 5
				case "medium":
					severity = yellow(strings.ToUpper(ePOItem.Severity))
					spaceAfter = 3
				case "low":
					severity = cyan(strings.ToUpper(ePOItem.Severity))
					spaceAfter = 6
				case "info":
					severity = white(strings.ToUpper(ePOItem.Severity))
					spaceAfter = 4
				}
			}

			title := ePOItem.PlayName + " - " + ePOItem.PolicyName
			var lineWithoutColour int
			if !ePOItem.IssuesFound {
				// Report OK message
				line := fmt.Sprintf(" |%s|       %s", severity, title)
				lineWithoutColour = len(fmt.Sprintf(" |%s|%s%s", "  ", "       ", title))
				fmt.Println(h.PadToWidth(line, " ", lineWithoutColour, false))
			} else {
				// if it's not just a resource to output, then output title too
				if !justAffectedResource {
					padding := strings.Repeat(" ", spaceAfter)
					lineWithoutColour = len(fmt.Sprintf(" |%s|%s%s", ePOItem.Severity, padding, title))
					line := fmt.Sprintf(" |%s|%s%s", severity, padding, title)
					fmt.Println(h.PadToWidth(line, " ", lineWithoutColour, false))
				}

				var resourceLine string

				output := ePOItem.createReportLine()

				if output != "" {
					resourceLine = fmt.Sprintf("             - %s", output)
					fmt.Println(h.PadToWidth(resourceLine, " ", 0, false))
				}

			}

		}

	}
}
