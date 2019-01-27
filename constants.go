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

var (
	severities = map[string]int64{
		"critical": 4, // Red
		"high":     3, // Magenta
		"medium":   2, // Yellow
		"low":      1, // Cyan
		"info":     0, // Blue
	}

	badRegions = map[string][]string{
		"ec2":        {"cn-north-1", "cn-northwest-1", "us-gov-west-1", "us-gov-east-1"},
		"cloudtrail": {"cn-north-1", "cn-northwest-1", "us-gov-west-1", "us-gov-east-1"},
		"config":     {"cn-north-1", "cn-northwest-1", "us-gov-west-1", "us-gov-east-1"},
		"kms":        {"us-gov-west-1", "us-gov-east-1"},
	}
)

const (
	crUser                      = iota
	crArn                       = iota
	crUserCreationTime          = iota
	crPasswordEnabled           = iota
	crPasswordLastUsed          = iota
	crPasswordLastChanged       = iota
	crPasswordNextRotation      = iota
	crMfaActive                 = iota
	crAccessKey1Active          = iota
	crAccessKey1LastRotated     = iota
	crAccessKey1LastUsedDate    = iota
	crAccessKey1LastUsedRegion  = iota
	crAccessKey1LastUsedService = iota
	crAccessKey2Active          = iota
	crAccessKey2LastRotated     = iota
	crAccessKey2LastUsedDate    = iota
	crAccessKey2LastUsedRegion  = iota
	crAccessKey2LastUsedService = iota
	crCert1Active               = iota
	crCert1LastRotated          = iota
	crCert2Active               = iota
	crCert2LastRotated          = iota
)
