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

	"fmt"

	"github.com/pkg/errors"
)

func GetResourceParts(input string) (service, resource string, err error) {
	colonPos := strings.Index(input, ":")
	if colonPos < 2 {
		err = errors.WithMessage(err, fmt.Sprintf("missing colon or invalid resource: %s", input))
		return
	}
	service = input[0:colonPos]
	resource = input[colonPos+1:]
	return
}

func GetignoredResourceParts(input string) (accountID, region, service, resource, resourceID string, err error) {
	// <acc id>:<region:<service>:<resource>:<resource-id>
	numColons := strings.Count(input, ":")
	if numColons != 4 {
		err = errors.Errorf("ignored resource string: '%s' is invalid", input)
	}
	accountID = strings.Split(input, ":")[0]
	region = strings.Split(input, ":")[1]
	service = strings.Split(input, ":")[2]
	resource = strings.Split(input, ":")[3]
	resourceID = strings.Split(input, ":")[4]
	return
}

// func MapKey(m map[string]int64, value int64) (key string, ok bool) {
//	for k, v := range m {
//		if v == value {
//			key = k
//			ok = true
//			return
//		}
//	}
//	return
// }
