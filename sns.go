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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"sync"

	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
)

var snsClientByAccountAndRegion map[string]snsiface.SNSAPI
var snsClientByAccountAndRegionMutex sync.Mutex

func getSNSClient(l []interface{}, session *session.Session, accID, region string) (output snsiface.SNSAPI) {
	snsClientByAccountAndRegionMutex.Lock()
	if snsClientByAccountAndRegion == nil {
		snsClientByAccountAndRegion = make(map[string]snsiface.SNSAPI)
	}
	if len(s3SClientByAccountAndRegion) == 0 {
		snsClientByAccountAndRegion = make(map[string]snsiface.SNSAPI)
	}
	if s3SClientByAccountAndRegion[accID+region] != nil {
		output = snsClientByAccountAndRegion[accID+region]
	} else {
		output = sns.New(session, aws.NewConfig().WithRegion(region))
		snsClientByAccountAndRegion[accID+region] = output
	}
	snsClientByAccountAndRegionMutex.Unlock()
	return
}
