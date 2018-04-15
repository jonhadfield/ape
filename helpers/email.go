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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

// type createEmailInput struct {
//	Region     string
//	CharSet    string
//	Source     string
//	Recipients []string
//	Subject    string
//	HTML       string
// }
//
// func CreateEmail(input createEmailInput) (emailInput ses.SendEmailInput, err error) {
//	recipients := make([]*string, 0, len(input.Recipients))
//
//	for _, recipient := range input.Recipients {
//		recipients = append(recipients, &recipient)
//	}
//	dest := ses.Destination{
//		ToAddresses: recipients,
//	}
//	subject := ses.Content{
//		Charset: &input.CharSet,
//		Data:    &input.Subject,
//	}
//	htmlBody := ses.Content{
//		Charset: &input.CharSet,
//		Data:    &input.HTML,
//	}
//	var body ses.Body
//	body.SetHtml(&htmlBody)
//	message := ses.Message{
//		Subject: &subject,
//		Body:    &body,
//	}
//
//	emailInput = ses.SendEmailInput{
//		Destination: &dest,
//		Message:     &message,
//		Source:      &input.Source,
//	}
//	return
// }

func Send(input ses.SendEmailInput, region string) (err error) {
	sess, err := session.NewSession()
	if err != nil {
		return
	}
	svc := ses.New(sess, &aws.Config{Region: &region})
	_, err = svc.SendEmail(&input)
	if err != nil {
		return
	}
	return
}
