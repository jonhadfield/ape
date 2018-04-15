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
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func StringSliceToLower(input []string) (output []string) {
	output = Map(input, strings.ToLower)
	return
}

func StringInSliceContents(a string, list []string) bool {
	for _, b := range list {
		if strings.Contains(a, b) {
			return true
		}
	}
	return false
}

func PadToWidth(input string, char string, inputLengthOverride int, trimToWidth bool) (output string) {
	// Split string into lines
	var lines []string
	var newLines []string
	if strings.Contains(input, "\n") {
		lines = strings.Split(input, "\n")
	} else {
		lines = []string{input}
	}
	var paddingSize int
	for i, line := range lines {
		width, _, _ := terminal.GetSize(0)
		if width == -1 {
			width = 80
		}
		// No padding for a line that already meets or exceeds console width
		var length int
		if inputLengthOverride > 0 {
			length = inputLengthOverride
		} else {
			length = len(line)
		}
		if length >= width {
			if trimToWidth {
				output = line[0:width]
			} else {
				output = input
			}
			return
		} else if i == len(lines)-1 {
			if inputLengthOverride != 0 {
				paddingSize = width - inputLengthOverride
			} else {
				paddingSize = width - len(line)
			}
			if paddingSize >= 1 {
				newLines = append(newLines, fmt.Sprintf("%s%s\r", line, strings.Repeat(char, paddingSize)))
			} else {
				newLines = append(newLines, fmt.Sprintf("%s\r", line))
			}
		} else {
			var suffix string
			newLines = append(newLines, fmt.Sprintf("%s%s%s\n", line, strings.Repeat(char, paddingSize), suffix))
		}
	}
	output = strings.Join(newLines, "")
	return
}

func GetStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str, end)
	return str[s:e]
}
