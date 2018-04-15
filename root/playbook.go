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

package root

// PlaybookTarget represents the IAM Roles and Accounts to run the playbook against
type PlaybookTarget struct {
	RoleType string `yaml:"roleType"`
	Include  []string
	Exclude  []string
}

// Filter represents the criteria used to match specific resources
type Filter struct {
	Criterion  string
	Comparison string
	Unit       string
	Value      string
	Values     []string
}

// Play represents the items within the playbook yaml file
type Play struct {
	Name            string
	Regions         []string
	Policies        []string
	Targets         []PlaybookTarget
	IgnoreResources []string `yaml:"ignore_resources"`
}

// Email has the settings to be used to connect to a mail server and what the propertie of the email to send
type Email struct {
	Provider   string
	Host       string
	Port       string
	Username   string
	Password   string
	Region     string
	Source     string
	Subject    string
	Recipients []string
	Threshold  string
}

// Slack is the settings used to post messages to a slack channel
type Slack struct {
	Channel   string
	Token     string
	Username  string
	Threshold string
}

// Playbook represents the parsed playbook yaml file
type Playbook struct {
	AccountsFile string `yaml:"accounts"`
	PoliciesFile string `yaml:"policies"`
	Plays        []Play
	Email        Email
	Slack        Slack
	Targets      []PlaybookTarget
}

// Configs represents the parsed and validated playbook, policies and accounts
type Configs struct {
	Playbook Playbook
	Policies Policies
	Accounts []Account
}
