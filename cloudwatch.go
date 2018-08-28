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

	"fmt"

	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	h "github.com/jonhadfield/ape/helpers"
)

var cloudwatchClientByAccountAndRegion map[string]cloudwatchiface.CloudWatchAPI
var cloudwatchClientByAccountAndRegionMutex sync.Mutex

func getCloudwatchClient(l []interface{}, session *session.Session, accID, region string) (output cloudwatchiface.CloudWatchAPI) {
	cloudwatchClientByAccountAndRegionMutex.Lock()
	if cloudwatchClientByAccountAndRegion == nil {
		h.Debug(l, "initialising cloudwatchClientByAccountAndRegion")
		cloudwatchClientByAccountAndRegion = make(map[string]cloudwatchiface.CloudWatchAPI)
	}
	if cloudwatchClientByAccountAndRegion[accID+region] != nil {
		h.Debug(l, fmt.Sprintf("reusing existing cloudwatchClientByAccountAndRegion client: %s", accID+region))
		output = cloudwatchClientByAccountAndRegion[accID+region]
	} else {
		h.Debug(l, fmt.Sprintf("getting new cloudwatchClientByAccountAndRegion client: %s", accID+region))
		output = cloudwatch.New(session, aws.NewConfig().WithRegion(region))
		cloudwatchClientByAccountAndRegion[accID+region] = output
	}
	cloudwatchClientByAccountAndRegionMutex.Unlock()
	return
}

var cloudwatchLogsClientByAccountAndRegion map[string]cloudwatchlogsiface.CloudWatchLogsAPI
var cloudwatchLogsClientByAccountAndRegionMutex sync.Mutex

func getCloudwatchLogsClient(l []interface{}, session *session.Session, accID, region string) (output cloudwatchlogsiface.CloudWatchLogsAPI) {
	cloudwatchLogsClientByAccountAndRegionMutex.Lock()
	if cloudwatchLogsClientByAccountAndRegion == nil {
		h.Debug(l, "initialising cloudwatchLogsClientByAccountAndRegion")
		cloudwatchLogsClientByAccountAndRegion = make(map[string]cloudwatchlogsiface.CloudWatchLogsAPI)
	}
	if cloudwatchLogsClientByAccountAndRegion[accID+region] != nil {
		h.Debug(l, fmt.Sprintf("reusing existing cloudwatchLogsClientByAccountAndRegion client: %s", accID+region))
		output = cloudwatchLogsClientByAccountAndRegion[accID+region]
	} else {
		h.Debug(l, fmt.Sprintf("getting new cloudwatchLogsClientByAccountAndRegion client: %s", accID+region))
		output = cloudwatchlogs.New(session, aws.NewConfig().WithRegion(region))
		cloudwatchLogsClientByAccountAndRegion[accID+region] = output
	}
	cloudwatchLogsClientByAccountAndRegionMutex.Unlock()
	return
}
