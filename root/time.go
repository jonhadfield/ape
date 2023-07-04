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

import (
	"strconv"
	"time"

	"github.com/pkg/errors"
)

func ProcessTimeFilterValue(filter *Filter) (filterValue time.Time, err error) {
	// Time based criterion prep
	var loc *time.Location
	loc, err = time.LoadLocation("UTC")
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	now := time.Now().In(loc)
	var int64val int64
	int64val, err = strconv.ParseInt(filter.Value, 10, 64)
	if err != nil {
		err = errors.New("value could not be parsed as 64 bit integer")
		return
	}
	switch filter.Unit {
	case "days":
		difference := time.Duration(int64val) * (time.Hour * 24)
		filterValue = now.Add(-difference)
	case "hours":
		int64val, err = strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Hour
		filterValue = now.Add(-difference)
	case "minutes":
		int64val, err = strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Minute
		filterValue = now.Add(-difference)
	case "seconds":
		int64val, err = strconv.ParseInt(filter.Value, 10, 64)
		difference := time.Duration(int64val) * time.Second
		filterValue = now.Add(-difference)
	default:
		if filter.Unit == "" {
			err = errors.New("unit not supplied")
		} else {
			err = errors.New("invalid unit supplied")
		}
	}
	return
}
