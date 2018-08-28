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

package presets

import (
	"fmt"
	"os"

	"io/ioutil"

	h "github.com/jonhadfield/ape/helpers"
	"github.com/pkg/errors"
)

var presetList = map[string]string{
	"cis-foundations": "checks defined here: " +
		"https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
	"kms": "Key Management Service best practices (under development)",
}

func List() {
	for k, v := range presetList {
		fmt.Println("\nNAME:", k, "\nDESC:", v)
	}
	os.Exit(0)
}

func Generate(l []interface{}, name string) {
	var err error
	if _, ok := presetList[name]; ok {
		var playbookData, policiesData []byte
		playbookPath := fmt.Sprintf("presets-files/%s/playbook.yml", name)
		policiesPath := fmt.Sprintf("presets-files/%s/policies.yml", name)
		playbookData, err = Asset(playbookPath)
		if err != nil {
			errMess := fmt.Sprintf("error: failed to generate playbook file for: '%s'", name)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
		policiesData, err = Asset(policiesPath)
		if err != nil {
			errMess := fmt.Sprintf("error: failed to generate policies file for: '%s'", name)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}

		playbookOutputPath := "playbook.yml"
		policiesOutputPath := "policies.yml"

		if _, err = os.Stat(playbookOutputPath); err == nil {
			errMess := fmt.Sprintf("failed to generate playbook as '%s' "+
				"already exists in this directory", playbookOutputPath)
			err = errors.New(errMess)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
		if _, err = os.Stat(policiesOutputPath); err == nil {
			errMess := fmt.Sprintf("failed to generate policies as '%s' "+
				"already exists in this directory", policiesOutputPath)
			err = errors.New(errMess)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(playbookOutputPath, playbookData, 0644)
		if err != nil {
			errMess := fmt.Sprintf("failed to write '%s'", playbookOutputPath)
			err = errors.New(errMess)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(policiesOutputPath, policiesData, 0644)
		if err != nil {
			errMess := fmt.Sprintf("failed to write '%s'", policiesOutputPath)
			err = errors.New(errMess)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
	} else {
		errMess := fmt.Sprintf("preset '%s' does not exist", name)
		err = errors.New(errMess)
		h.Error(l, errMess)
		h.OutputError(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func Load(l []interface{}, name string) (playbookData, policiesData []byte) {
	var err error
	if _, ok := presetList[name]; ok {
		playbookPath := fmt.Sprintf("presets-files/%s/playbook.yml", name)
		policiesPath := fmt.Sprintf("presets-files/%s/policies.yml", name)
		playbookData, err = Asset(playbookPath)
		if err != nil {
			errMess := fmt.Sprintf("error: failed to generate playbook file for: '%s'", name)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
		policiesData, err = Asset(policiesPath)
		if err != nil {
			errMess := fmt.Sprintf("error: failed to generate policies file for: '%s'", name)
			h.Error(l, errMess)
			h.OutputError(err)
			os.Exit(1)
		}
	} else {
		errMess := fmt.Sprintf("preset '%s' does not exist", name)
		err = errors.New(errMess)
		h.Error(l, errMess)
		h.OutputError(err)
		os.Exit(1)
	}
	return
}
