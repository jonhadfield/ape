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
	"strconv"
)

func ToInt64(input interface{}) (output int64, err error) {
	switch v := input.(type) {
	case int64:
		return input.(int64), nil
	case string:
		return strconv.ParseInt(v, 10, 64)

	}
	return
}

func NumBetween(value, floor, ceiling int64) (result bool) {
	if value >= floor && value <= ceiling {
		result = true
	}
	return
}
