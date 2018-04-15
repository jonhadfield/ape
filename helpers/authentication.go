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

package helpers

import (
	"fmt"

	"os"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
)

func GetSession() (sess *session.Session) {
	sess, err := session.NewSession()
	if err != nil {
		OutputError(err)
		os.Exit(1)
	}
	return sess
}

type GetAssumeRoleCredsInput struct {
	Sess       *session.Session
	AccountID  string
	RoleArn    string
	RoleName   string
	ExternalID string
}

func GetAssumeRoleCreds(input GetAssumeRoleCredsInput) (creds *credentials.Credentials, err error) {
	var roleArn string
	if input.RoleArn != "" {
		roleArn = input.RoleArn
	} else {
		roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", input.AccountID, input.RoleName)
	}
	// TODO: Test without external id specified
	creds = stscreds.NewCredentials(input.Sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.ExternalID = &input.ExternalID
	})
	_, err = creds.Get()
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}
