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

package iam

import (
	"encoding/json"
	"time"
)

type Policy struct {
	Arn              string
	Version          string
	PolicyDocuments  []PolicyDocument
	DefaultVersionID string
}

type PolicyDocument struct {
	Version      string
	Statement    []PolicyStatement
	CreationTime *time.Time
}

type PolicyStatement struct {
	Effect   string
	Action   []string
	Resource []string
}

type RawPolicyDocument struct {
	Version   string
	Statement json.RawMessage
}

type RawStatementEntry struct {
	Effect   string
	Action   json.RawMessage
	Resource json.RawMessage
}
