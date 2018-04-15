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
	"strings"

	"github.com/jonhadfield/ape/root"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
)

type PostSlackMessageInput struct {
	User    string
	Color   string
	PreText string
	Title   string
	Text    []string
}

func PostSlackMessage(config root.Slack, input PostSlackMessageInput) (err error) {
	client := slack.New(config.Token)

	attachment := slack.Attachment{
		Color:   input.Color,
		Pretext: input.PreText,
		Title:   input.Title,
		Text:    strings.Join(input.Text, "\n"),
	}
	attachments := []slack.Attachment{attachment}
	pmParams := slack.PostMessageParameters{
		Username:    config.Username,
		AsUser:      true,
		Attachments: attachments,
	}
	_, _, err = client.PostMessage(config.Channel, "", pmParams)
	err = errors.WithStack(err)
	return
}
