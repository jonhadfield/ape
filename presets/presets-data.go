// Code generated by go-bindata.
// sources:
// presets-files/aws/playbook.yml
// presets-files/aws/policies.yml
// presets-files/cis-foundations/playbook.yml
// presets-files/cis-foundations/policies.yml
// presets-files/kms/playbook.yml
// presets-files/kms/policies.yml
// DO NOT EDIT!

package presets

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _presetsFilesAwsPlaybookYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x94\x41\x6f\xd3\x40\x10\x85\xef\xf9\x15\x4f\xf1\xd9\xe5\x50\x71\xc9\x2d\x09\x09\x42\x24\xc2\xf2\x52\xc1\x75\x59\x0f\xe9\xaa\xf6\x8e\x35\x33\xa6\x98\x5f\x8f\x9c\xb4\xa5\x2d\x87\x6a\x13\xf9\x32\xb6\xfc\xbe\x27\xcf\x7b\xde\xa2\x2c\xcb\x59\xd1\x73\x1b\x43\x24\x5d\xe0\xea\xdd\xe3\x7c\x35\x76\xed\xac\x98\x15\x7d\xeb\x47\x5d\xcc\x0a\x00\x25\x92\xef\x68\x81\xf9\x66\xe5\xd0\x0f\x3f\xda\x18\xa0\xc9\xf7\x7a\xcb\xa6\xf3\xe3\x2b\xc0\x13\xeb\xe1\x7e\x92\xcd\xe7\x2f\xf5\xcb\xce\xff\xe1\x84\xfa\x83\x43\x75\xc2\xb8\x0b\x31\x8e\xc2\x20\xd1\x46\x7c\x14\x1e\x7a\x2c\x43\x20\x55\xd4\x51\xef\xce\x01\xf2\x60\x84\xf7\xd7\xd8\x7f\x47\x4d\xca\x83\x04\x42\x4d\x81\xa5\x81\x23\x53\xf8\x34\x0d\xa9\x21\x41\x35\x61\x47\x6c\xc5\x77\x74\xcf\x72\x8e\x9d\xbb\xc6\x6a\x08\x77\x64\xa8\x48\xba\xa8\x1a\x39\xe5\xed\xe1\x9b\xc3\xba\xe5\xa1\xf9\x2a\x3e\xb6\xd8\xf1\xe1\x10\xd3\x21\x87\x70\x54\x6f\x85\x93\x61\x3d\xa8\x71\x07\xe7\x76\x58\x93\x58\xfc\x19\x83\x37\x52\xc4\x04\xbb\x25\x7c\x5a\xee\x9f\x3f\x87\x33\x16\x3a\xd3\xea\x95\x07\xf8\x64\xf1\x45\xe2\x21\x26\x38\x92\x5f\x24\x39\xe8\xcd\x6e\x85\x5d\x54\xa3\x44\xf2\xd4\x88\x5c\xc0\xcb\x26\x65\xe5\xb0\xf9\xdd\xb3\x52\xf3\xd8\xbe\xcf\x34\x66\xc9\xa7\xd5\xfe\x93\xa2\x66\xf3\x16\x39\xe5\x22\x2a\xaf\x7a\x3f\x55\xf5\x54\xcd\x5c\xf9\x8d\x66\xc5\x79\xe9\x51\xb0\xdf\x2e\x71\xfc\xe5\xd8\xa6\x8f\xe7\x21\x59\x8e\xfc\x55\x5a\x28\xe1\x7a\x0a\x53\xa1\x50\xb1\x98\xe2\x26\x09\xa9\x49\x0c\x46\xcd\x65\xe0\xe7\xa4\x87\x9c\xde\x02\xfe\x77\xfd\x0d\x00\x00\xff\xff\xda\x99\x97\xba\x6f\x05\x00\x00")

func presetsFilesAwsPlaybookYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesAwsPlaybookYml,
		"presets-files/aws/playbook.yml",
	)
}

func presetsFilesAwsPlaybookYml() (*asset, error) {
	bytes, err := presetsFilesAwsPlaybookYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/aws/playbook.yml", size: 1391, mode: os.FileMode(420), modTime: time.Unix(1535407695, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _presetsFilesAwsPoliciesYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00")

func presetsFilesAwsPoliciesYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesAwsPoliciesYml,
		"presets-files/aws/policies.yml",
	)
}

func presetsFilesAwsPoliciesYml() (*asset, error) {
	bytes, err := presetsFilesAwsPoliciesYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/aws/policies.yml", size: 0, mode: os.FileMode(420), modTime: time.Unix(1533844447, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _presetsFilesCisFoundationsPlaybookYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x58\x4d\x6f\xdb\x48\x0c\xbd\xe7\x57\x10\x3e\xb5\x05\x92\xc6\x71\x77\xb7\xc9\xcd\xf0\xa2\x40\xd0\xb8\x08\x90\xa2\xbd\xf4\x42\x8f\x28\x69\x90\xd1\x8c\x76\x3e\xe2\x6a\x7f\xfd\x82\x23\xc5\x5f\x1d\x2b\xd3\x24\x58\x14\x28\x62\x79\xc4\xc7\x21\x1f\x1f\x49\x9f\x9e\x9e\x9e\xb4\x46\x49\x21\xc9\x5d\xc1\xd9\xfb\xc7\xbf\xcf\xba\x46\x9d\x9c\xb4\x0a\x3b\x77\x75\x02\x00\xa7\xa0\xb1\xa1\x2b\x98\x2c\xae\xef\x60\x7a\x36\x9d\xf0\x43\x80\xcd\xab\xfd\x47\x3e\x37\xb1\x24\x48\x7b\xb0\xc6\x78\x68\xd1\xb9\xb5\xb1\x05\x04\x87\x15\x4d\x8e\x9c\x42\x21\xc8\x39\xb8\xa7\x6e\xe7\xdc\x01\xe2\xc5\x08\x62\x70\x64\x1d\xac\xa5\xaf\xb7\x80\xa8\x8b\xf8\xc4\x04\x0f\xcb\x4f\xf3\x94\xc9\xd9\x6f\x9a\xd4\xc6\x43\x70\x54\x80\xd4\x70\x79\x0e\x05\x76\x6e\x92\x7e\x05\x85\x97\x0f\xb4\x7b\xaf\x63\xef\x1e\xb8\xf4\x61\xc4\x25\xd2\x2e\xd8\x5d\xa3\x0e\xd0\x12\x58\xe3\xd1\x53\x01\xf4\x40\xb6\x1b\xb3\xfd\xc7\xd3\xb6\xaf\xe7\xcb\xed\x75\xe3\xb9\x0e\x2c\xfd\x13\xa4\x25\x07\xe8\x41\x11\x3a\x0f\x46\x13\x84\xb6\x25\x2b\xd0\x11\x28\xf2\x9e\x6c\x0a\xf0\xcf\x17\x01\xee\xe3\x29\xb3\x7e\x12\xef\xaf\x57\xc4\x73\x5d\xb3\x32\x2a\x85\xf2\xf1\x15\x51\x74\x68\x56\xe9\xbb\x5c\xbe\x30\x59\x8d\xd4\xb2\x09\x0d\x28\xd2\x95\xaf\xc1\x94\x30\xfd\x00\xc6\x42\x65\x09\x8f\x84\x6f\x7a\xfe\x3c\xcc\xd6\xd2\x03\x69\xef\xb6\x5f\x58\x0a\x2e\x59\xc4\xd3\x31\xdd\x18\x81\xa0\x9f\x6d\xbc\xd5\xe3\xf3\xbe\xcc\xb6\xa5\xc4\x37\x53\xe4\x92\xb4\x9f\x8e\x29\xc7\x80\xa9\xcd\x46\x88\x4c\xd0\x7b\x82\x44\x3f\xa5\xf3\x69\xc3\x63\xfa\x31\x18\x5e\x7e\x9a\x83\x74\x40\x1a\x57\x8a\x0a\x28\x8d\x05\x5f\xd3\x1e\x58\xd2\x74\x86\x0e\xd4\x68\x8b\x35\xbe\x00\x23\xb7\x3c\x87\xaf\xa3\xd8\xa0\xf7\x28\x6a\x2a\xc0\x68\xd5\x81\x37\x50\x59\x13\xda\x18\x7f\x6b\x14\x39\x78\x73\xad\x95\xd4\xf4\xf6\x7f\x44\x9c\x0f\x27\xd2\x98\x99\xe5\xba\x44\xe7\xa9\x37\xc9\xc1\xec\x05\xfc\x65\x06\x35\x56\x59\x16\x2f\x32\x08\x8a\xe0\x42\xdb\x1a\xeb\x7b\x7b\x35\x3a\x58\x11\x69\x10\xb1\x9c\x0b\x8e\x4b\x13\x01\x41\x6a\x21\x8b\x58\x8e\xb1\x13\xcd\xbf\xdf\xc1\x5d\xff\x6a\x12\x7b\x8c\xc3\x7f\x9b\xd8\xb6\x1c\xf9\xd0\xee\xb5\x9d\x22\x58\xa9\x2b\x90\x5a\x7a\x89\x8a\xfb\x9a\x1d\x4e\x31\xf9\x50\xa9\x18\x81\xbe\x1f\xfa\x1a\x3d\xd4\xc8\xdd\x10\x84\xd1\x8e\xdd\x7f\x2c\xe3\xa4\x47\x19\xd4\xdf\x23\x49\x04\x40\xa5\xcc\x1a\xca\xa0\x14\xfc\x98\xbc\xbb\x7a\xf7\x63\x02\x58\xb0\x06\x3a\x6f\x31\xf6\xe2\xd6\xca\x07\xa9\xa8\x1a\x68\xc5\x17\x1b\x82\xf7\xab\x17\x17\xa3\xf3\xcd\xe0\xc4\x42\x99\x50\x7c\xb5\x28\xd5\x6e\xf5\x49\x1d\xef\x6f\xa9\x92\x46\x27\x64\xe3\x62\x74\x90\xf9\xd5\xb4\x32\x15\x94\x52\x11\x3c\xa0\x92\x05\x7a\x69\xf4\x0e\x5c\xca\x7e\x86\x2a\xb1\x3c\xdc\xcd\x60\x15\xc4\x3d\xf9\x03\x34\xc7\x5c\x92\x2e\x06\xa8\x0d\x2b\x25\x85\xea\x86\xe4\xcb\x95\x4a\x10\xf8\x22\x67\x68\xd9\xc1\xf0\xfc\x7f\x9f\x04\xa9\x3d\x55\x36\x12\x38\x92\x35\x9e\xfa\x8e\x5e\xd4\x70\x63\xaa\x64\xf4\x32\x86\x18\xa6\xfc\xc2\xe8\x52\x56\xc7\x13\x03\x6f\xfa\x0f\xce\x04\x2b\x08\xbe\x76\x2d\xb9\xb7\x93\xe7\xda\xaa\x94\x59\xe1\x8e\x39\xff\x32\x73\x6e\x93\x9a\x82\x4a\xa9\x1f\x95\xed\x59\xa6\x34\xe7\xb3\x95\x62\xdf\xd4\x41\x50\x33\x74\x79\x4b\x97\x41\x08\x94\xa9\xaa\x28\x02\x5b\x70\xa3\x23\xb3\x76\x72\xbd\x79\x2b\x85\x9a\x31\xae\x1d\x52\x93\x49\x43\x5a\xd8\xae\x65\xce\xa0\xe7\x90\xf3\x5c\xcd\x8e\x7c\x5e\xde\xc1\x62\xf9\x39\xc9\x9a\x0c\xcd\x8e\x63\x34\x57\x17\x4b\x98\x08\xce\x9b\x86\xec\x46\x5f\xd9\xf0\x68\xdd\xcd\x72\x24\x03\x63\x39\x37\xe4\xad\x14\x5c\xd5\xdc\x71\x78\x4f\x41\x85\xb6\xe9\x27\x8d\x08\x1f\x34\x06\x5f\x1b\x2b\xff\xa5\x02\xe6\xb7\xd7\x20\x50\xa9\xc4\xc5\x66\x39\x62\x92\x0b\xda\x37\xac\x86\x97\xb2\xc5\xa0\xd3\x4e\x56\xfa\x54\xea\xf1\x3d\x6a\x96\xa3\x38\xd9\x37\xe7\xf5\x8f\xa7\xd5\xf1\xe9\x65\x96\xb5\x28\x65\x62\x6e\xba\x49\x07\xa2\x46\x5d\x51\x32\xd2\x19\xc2\x93\x0b\xb8\xc3\x6a\x11\x2b\x38\xd8\x9e\x7a\x23\xf0\x19\x25\x9a\x0b\xcf\xca\x91\x48\x36\x53\x8e\xb4\x97\x62\x28\x03\x94\x2a\xd8\xb4\x33\x19\x95\x9b\xeb\x4c\x21\x1d\xae\x14\xd7\xaf\xb1\xe0\x78\x8c\x0b\x2c\x25\x05\x29\x8a\x6e\x98\x32\x5d\x8c\x29\xb7\x32\xaa\x3c\xd7\xad\xad\xdc\x3d\xcd\x8c\x8c\x55\xed\x77\x52\x33\x88\x7a\x36\x33\x72\xd6\xb6\x5c\x7c\x47\x22\x58\xe9\xbb\x7e\xc8\x1e\x45\x7d\x45\xb9\x1b\x60\x78\xf0\xf8\x42\x7e\x6d\xec\x3d\xcc\xfb\x26\xb3\x30\xda\x5b\xa3\xe0\x86\x77\x30\x78\xf3\x65\xbe\xb8\x49\x34\xb0\x59\xd6\x8e\xf7\x0c\x6f\xf4\xe0\x4d\x85\x9e\xd6\xc9\x5f\x55\x66\x59\x5b\x60\x2e\xb4\x35\xc1\x13\x78\x6e\x31\xa3\xb1\x7f\x45\xf1\xfb\x76\xbb\x38\x0e\xf5\x21\xa7\xa9\x69\x73\x40\x1b\x37\x4c\xe3\x52\x57\x96\x93\x58\x5a\xd3\xc0\xf9\x59\xfc\xf7\xfe\x9c\xe3\x1a\x17\x99\x61\xed\x39\x00\xcc\x5b\xd6\x9f\x05\x38\x9b\x7d\xbc\x4c\x41\x1e\x4b\xe0\x16\x91\x83\x54\x32\x42\x62\xe8\x19\x26\xae\x6f\xb7\x8b\x64\x00\x33\x52\xc5\x33\x53\x41\x25\x06\xe5\x0f\x0b\xd0\x94\xc3\xcf\x7a\xec\x01\xcf\x3a\x56\x0a\x1f\xaf\xcb\x63\x74\x59\x4a\x31\x39\xf9\x2f\x00\x00\xff\xff\xdc\x5b\xf7\xe1\xc2\x15\x00\x00")

func presetsFilesCisFoundationsPlaybookYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesCisFoundationsPlaybookYml,
		"presets-files/cis-foundations/playbook.yml",
	)
}

func presetsFilesCisFoundationsPlaybookYml() (*asset, error) {
	bytes, err := presetsFilesCisFoundationsPlaybookYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/cis-foundations/playbook.yml", size: 5570, mode: os.FileMode(420), modTime: time.Unix(1533844447, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _presetsFilesCisFoundationsPoliciesYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x5a\x5d\x6f\xdb\x3a\xd2\xbe\xef\xaf\x18\xf8\xaa\x6f\x81\xbc\xa7\x6d\xce\xc5\xd6\xd8\xb3\x80\xd6\x69\x1a\x23\x76\x6a\xd8\xf9\xb8\x39\x37\x34\x35\x92\x88\x50\xa4\x96\x1f\xf1\xf1\xfe\xfa\x05\x49\xc9\x76\x6c\x39\x96\x1d\x29\xe9\x62\xdb\x9b\xd6\x12\x39\xcf\x33\x33\x9c\x79\x46\xd2\xd9\xd9\xd9\x87\x42\x72\x46\x19\xea\xfe\x07\x80\x33\x10\x24\xc7\x3e\xf4\x14\x52\x14\x06\x94\x94\x06\x0a\xa2\xf5\x42\xaa\x18\xac\x26\x29\xf6\x3e\x00\x00\x68\x7c\x42\xc5\xcc\xb2\x0f\x3d\x2e\x17\xe1\x37\x85\x5a\x5a\x45\xb1\x0f\x8c\xe4\xfd\x3b\x8d\xca\xff\x9c\x30\x6e\x50\xf9\xed\xdd\x9f\x33\xa0\x8a\x19\x54\x4c\x8a\x3e\xb8\x9b\x6e\x48\x8e\xe5\x35\x00\x2a\xf3\x82\x28\xa6\xdd\xc5\xde\x1f\x7f\xf4\x56\x17\x9e\x08\xb7\x1e\x98\x94\xa6\x57\xb7\xd5\xa4\x44\x39\x22\xda\xdc\x69\x8c\xeb\xb7\xfc\xfb\x7a\x47\x2b\x98\xe9\x43\x4c\x96\x7a\xdb\xc8\xf9\xe7\x0f\xfb\x7c\x41\x28\x45\xad\xe1\x11\x97\x7b\xbc\x91\x63\xcc\x6c\xfe\x2b\x38\x24\xa2\x86\x3d\x61\xe4\x01\x5f\xe3\x52\xb7\xe0\x98\x6f\xcf\x1d\x63\x35\x2a\x0d\x0b\x66\xb2\x75\x8e\x10\x11\xfb\x5f\xa4\x35\x30\xbe\x8c\x76\xfc\xe3\x00\x32\x4a\xf8\xc9\x1e\xba\x22\x7a\x7c\x19\x5d\xe0\x13\xa3\xb8\xe3\x8c\x84\x70\x8d\xb5\xde\xb8\x22\xba\xca\x90\x9d\x55\x46\x59\xec\x1d\x64\x26\xa4\x01\xab\x31\x06\x26\xe0\xdb\x67\xef\x9f\x1d\x76\x19\x4b\xb3\xd7\x30\x3b\x00\xf1\xe4\xb4\xff\xc7\xeb\xa2\x4b\x7c\x2a\x6d\x26\x7f\x13\x67\xbc\xf2\x28\x1c\x97\xbf\xa7\x30\x44\xa1\xad\xda\xa4\xa5\x81\x28\x04\x25\x0d\x31\x18\x83\x63\xb2\x7c\x4b\x76\xd3\x60\xb8\x75\x82\xc3\x68\xbc\x4e\x63\x5f\xee\x97\xa0\xf0\x5f\x96\x29\xd4\x40\x0c\x70\x24\xda\x80\x14\x08\xb6\x28\x50\x51\xa2\x11\x38\x1a\x83\xaa\x71\x82\x57\x69\x38\xf1\xbb\x1f\x64\x3f\x0d\xd6\x23\x33\x72\xa6\x7f\x0a\xbc\x73\x86\x07\x44\xe3\xc8\xdb\xdd\x77\xb0\x8f\x23\xf7\x9c\x1b\x97\x8b\x97\xb9\xed\x8f\xe8\x6b\xd9\x8d\x9c\xe9\x6e\xd9\xe9\x65\x3e\x97\xfc\x0d\x39\xdd\x48\x11\xf1\x22\x23\xc2\xe6\xa8\x18\x1d\x64\x44\x11\xda\x11\x39\x61\xf3\xf9\x9b\x06\xec\xc6\x1b\x6c\x87\x8a\x86\x9c\x09\x96\xdb\x1c\x38\x8a\xd4\x64\x20\x13\xf8\xf2\x3b\x48\x05\xa9\x42\xd2\x69\x22\x8e\x83\xe1\x55\x8f\xf0\xf6\x0f\xf6\xff\x92\xed\x97\xdf\x9b\x12\x2d\x14\x3e\xa1\x30\x7a\x7d\x41\xa1\xd5\xc7\x68\xa3\x23\x79\x85\xf0\xfc\x4c\xaa\x65\xfa\x56\x4e\x31\xc7\x67\x31\x6b\x8d\x1d\xfe\x55\xf8\x28\x56\xbf\x87\x9e\xb8\xee\x7b\x2e\x92\x1c\x75\x73\x31\x70\x24\xd9\xea\xf6\xef\x0e\x07\x31\x4c\x8a\x89\xbb\x72\xb8\x4d\xbc\xd8\x13\x84\x5c\x09\x5a\x69\xc5\x33\x61\x8b\x7f\x31\x6d\x5a\xd6\x36\x2d\xea\xda\x2b\xa2\xb7\x9a\x67\x03\x41\x57\xb2\x1e\x5f\x46\xc0\x34\xa0\x20\x73\x8e\x31\x24\x52\x81\xc9\xf0\x99\x27\xda\x57\xac\xed\x72\x3f\x28\x7e\x6b\x68\x67\x44\xc5\x0b\x72\x22\xff\x5f\x64\xbe\xbb\x22\xfa\xaa\xa4\x71\x8a\x0b\xfc\xc9\x2e\x27\x5d\xaf\xf2\x88\x31\x84\x66\x18\x83\x14\x7c\x09\x46\x42\xaa\xa4\x2d\xfc\x69\x56\x92\xa3\x86\x8f\x43\xc1\x99\xc0\xff\x6b\x5b\xf9\x5d\x11\x1d\x76\x9e\x94\x70\x9a\xa7\xef\x09\x24\xa2\xf2\x8e\x2e\x68\x8c\x89\x20\x29\xc6\xa7\xf1\x18\x13\x6d\x30\xc0\x74\x29\x19\x46\x8c\x23\x40\x4e\x25\x0f\xf1\xcf\x65\xcc\x92\xa5\x42\x6d\xb9\xe9\x83\x6b\x45\x4a\xe3\xe1\x96\x2f\x39\xee\xcf\x4c\x2a\x85\x21\x4c\xe8\xdd\xfc\x0c\xb0\x5f\x60\xe5\x5c\xf2\xdf\x48\xcb\xe3\xae\xe5\x45\x40\xdb\xa2\x90\xca\x04\x56\x19\xd1\x30\x47\x14\x40\xbd\x7c\x89\x5d\xda\xe5\x7e\x39\x30\x41\x59\xec\x95\x80\x1f\x1b\xa3\x87\x19\xcc\xc2\xd2\xa6\x55\xe5\x95\xf4\xb7\x92\x72\x59\x65\x7f\xbd\x3b\x98\xd8\x72\xc4\x6a\xd3\xb0\x71\x8f\x28\xd1\x27\x0b\xdd\x77\xc8\xfc\x3f\x82\x24\xf8\x2d\x7a\x98\x95\xbc\x42\x0f\x7a\xee\xb6\x0b\xe9\xc7\x63\x8d\xc6\x16\xcf\x86\xcb\xd8\x2a\x26\x52\x60\x82\x19\x46\xb8\x9b\x9f\x55\x79\x97\x2b\xc4\x84\x73\x9f\x42\x61\xee\x36\x19\x31\x90\x11\x37\x75\x03\x95\x42\x3b\xcf\x57\x0a\xa4\xd5\x12\xbd\xdb\x4e\x07\x21\xae\x0f\xcc\x64\xab\x1d\x76\x8f\x75\xfd\x56\x77\xc2\x6a\x8c\x9b\xf5\xe7\xfa\x1d\x8e\x78\x4a\x53\x57\x15\xbd\xdf\x08\xe7\x72\x01\x89\xe5\x1c\xfe\xec\x7d\xea\x7f\xfa\xb3\x07\x24\x76\x2a\x5c\x1b\xa7\xa0\x9e\x10\x0a\xc5\x9e\x18\xc7\xb4\xac\xa3\x2e\x5e\x65\x3a\x37\x97\x71\xcd\xe4\x5b\xef\x1e\x95\x66\x72\x3b\xd5\x5c\x9e\x60\x42\x2c\xaf\xef\x76\xbd\xef\x49\x82\xd4\xec\x2e\x8a\xf8\x2a\xd8\xdb\x4b\xa6\x25\xbc\xdd\x45\x9f\xea\x17\xb8\x30\xd5\x01\xfb\x54\xeb\xe6\x01\x97\x36\xbe\x55\x84\xf1\x4d\x09\xc1\x84\x4f\x5c\x85\x29\x93\xa2\x99\x68\xa4\x6e\x23\xe3\x36\xea\xfb\xed\x0e\xbb\x70\xa8\xc7\x96\x1b\x36\xf5\x46\xfc\x9a\x5d\xd0\xfb\x5b\xff\x06\x70\x2e\x53\x67\x09\xdd\x2a\x16\x7b\x31\xbd\x41\xa6\x61\x99\x3e\x1e\xff\x48\xa6\x97\x8c\xe3\xfd\xca\xe8\xf7\x4d\x83\xcd\x58\x38\x9d\x36\x3b\x87\xb9\xa5\x8f\x68\xb6\x38\x69\x57\x83\x99\xf6\x69\x5c\xd8\x39\x67\x94\x2f\xcb\xca\xc3\xe6\x7c\xb7\xfd\xb4\x13\x95\x7f\x7a\x28\x93\xd2\x5e\xb4\x65\xae\xd1\xd1\xdd\xa0\xe1\x4d\x87\xd3\xc8\x84\xc1\x54\xf9\xde\xe2\xfb\x88\xbf\xeb\x81\x18\x9a\xc1\x48\xa6\x5d\x25\xd9\x88\x18\xd4\x66\x6d\xcb\x99\xba\x40\xce\x9e\x50\x2d\x6f\x59\xbe\x41\xeb\xc0\xc0\xf5\x65\xf5\xc3\xc6\x83\xba\x1a\xf2\xae\x3d\x0e\xa4\x48\x58\xba\xff\x40\xc1\xc7\xf0\x9f\x40\x0b\x6e\x97\x05\xea\x5d\x29\x57\xeb\x00\xbf\x73\x7f\x8a\x54\xaa\xb8\x41\x1f\x70\x95\xa5\x6c\x6a\x18\x57\xa5\xc4\xdb\x3b\x26\x4b\x9b\x71\x4a\xb9\x9c\x93\x0d\x5a\xa6\x43\x5a\x43\x41\xb9\x8d\xf1\x87\x37\xd9\x31\x2f\xbd\x3a\x9f\x31\x26\x4c\xd4\xa9\xee\x56\x38\x55\x69\x39\xc8\x88\x10\xc8\x67\xe7\xe1\x28\x3a\xe1\x77\x11\x0c\x77\xc0\x4d\xb8\x2a\x53\x30\xfa\xc6\xdc\x84\xbe\x75\x56\xa3\xe9\xcd\x09\xd4\xd6\x05\xb3\xd4\x61\x5c\xa6\xa9\xd7\x60\x6b\xa2\x52\xf8\xda\xba\x51\x8a\x56\xab\x3a\x2d\x9c\xa3\x00\xe5\x84\x56\xb0\x5d\xfc\x5d\xcd\x44\x41\xd5\xb2\x70\x25\x93\x18\x07\xce\x80\xd5\x8e\xe8\xf5\x78\x06\x83\xf1\x75\xd3\xf7\x17\x27\xf5\x36\xfd\xbd\x32\x7e\x0c\x0b\xff\x9a\xc5\x35\x60\x27\x7e\xa9\xd5\x46\xe6\xa8\x56\x43\x85\xc3\x7c\x7c\x6b\x7e\xcc\x75\xbf\x12\x9c\x2f\xa2\xbe\xc6\xe5\xb4\xb4\x7f\x28\x00\x75\xcb\x07\x25\xdc\x72\xd8\x38\xa2\xe3\x09\x09\x1a\xa9\x75\x2c\xaa\x61\x3d\xa8\x55\x26\x52\xe5\x32\x34\x51\x32\x87\xcf\xff\xef\xff\xfe\xf6\xd9\x35\x76\x3f\x7a\x7d\xfd\xda\x28\x19\x91\x7e\xed\xcf\xca\xfd\x7f\xb8\xed\x9b\x14\x48\x6f\x78\xa2\xa4\x91\x54\xf2\x3d\x6d\xce\x83\xac\x29\x99\xb7\x83\x49\xbd\x8b\xaa\x6d\x57\xc3\x5f\xe3\x2d\x2b\xaa\x7b\x76\x1c\x4e\x8e\xdc\x6f\xe5\xcc\x56\x03\x72\x7e\xfe\xb7\x6f\xff\x33\x21\x59\x93\x7d\x9b\xa0\xdc\x4f\x06\x90\xb8\x20\xd4\xd4\xeb\xb2\x31\xdd\x4f\x06\x4d\x8b\x9a\x8b\xc0\x7d\x41\x0f\xfb\xfd\x8a\xe8\xb2\x1a\x5c\x72\xb9\x18\xc9\xf4\x58\x81\x1e\x87\x91\x6e\x2b\xa3\x40\x26\xe5\xcb\x64\xc7\xcb\x15\x67\xc5\xa8\xf1\x79\xe6\x64\x6f\x92\x30\x7a\x04\x93\x23\x73\xc9\xdf\xe6\x94\xc1\x9e\x00\xd5\x3d\x84\x8d\x5f\x9a\x4c\xaf\x88\x8e\xc4\x72\x6a\x79\x9d\x82\xda\xad\x7b\x34\x43\xfa\xe8\x6b\x7c\xe8\xa9\xd5\x67\x15\x7e\x6c\x28\xdb\x72\xe3\x67\xee\xfa\xbc\x1f\x9a\x67\x23\x39\x2b\x17\x3a\x4c\x27\xd1\x86\x95\x97\xd1\xae\x1e\x79\xb9\x49\x31\x47\x17\xa8\xd2\x8c\xff\xb2\x85\x70\xa2\xf2\xf0\x82\xc4\x53\xb2\x82\x58\x93\x49\xc5\xfe\x8d\x31\x44\x93\x21\x50\xc2\x79\x77\xbd\xd6\xb9\xde\x21\x78\x60\x26\x9b\xd9\xb9\xa6\x8a\xcd\x51\x5d\x4a\x75\xb7\x81\x23\x9a\x0c\x07\x6b\x14\xcd\x72\xb7\x29\xdf\xd0\xef\x72\x14\xc6\x29\x46\xff\x50\x4a\xb3\x54\x9c\x31\xf1\xe2\x47\x3f\x9d\xf3\x2f\xc1\xcc\x58\x2a\x86\x42\x3f\x04\x28\x2b\x24\xed\xfa\xc0\x7f\xf7\xe5\x8e\xf4\x8b\x6f\x4d\x3a\xa7\x3c\x95\xd2\x44\xc1\xf8\xdd\xfa\x4b\xb4\x76\xa9\xae\x9e\xac\x2d\x81\x66\x44\xa4\xf8\x0e\xa9\x3d\x8c\xc6\xe1\x49\xdb\x60\x13\x41\xbb\x3c\x37\x04\x75\x98\x57\x6c\x78\xd1\xfa\x7e\xac\xd7\x88\xc2\x64\xd6\x21\x79\x37\xfe\xd5\x9c\x6b\x57\x50\x50\xb8\x2a\x1c\x44\x3a\x61\xdc\xaa\xf7\x70\x45\xf4\x30\x2b\x31\x45\xd6\x64\x97\xcf\x70\xb4\xeb\x89\x98\x69\x32\xe7\x4e\x6e\x48\x05\x9a\x66\x18\x5b\x27\x38\x62\xe4\xe8\x7d\x20\x93\xfa\x39\xe5\xed\x7d\x72\x51\x21\xfd\xa9\x66\x15\xce\x8b\x12\xe6\xcf\x64\x30\xbe\xee\xc2\x3d\xeb\x61\xfa\xbd\x6b\x42\xf5\xc0\xa3\xf3\xc2\xb0\xf1\x68\xe4\x57\x29\x0c\x5d\x97\x83\x2d\xe9\xfa\x7e\x31\x46\xea\xa5\x6b\x87\x54\x4b\x6e\x6e\xa4\xbb\x41\xb3\x90\xea\x11\x82\x52\x74\x31\x37\x4a\x72\x18\x31\x6d\x34\x7c\xbc\x89\x06\xa3\xa6\x2f\xd0\x5b\x74\x81\x33\xfb\x36\xf4\x45\x49\x3f\x25\x06\x17\xcd\xbf\x76\x6d\x93\x6b\x40\xf0\x23\x00\xe8\x90\xb5\x92\xd6\x20\x18\x37\xe5\xbd\x5f\x72\x4f\x1d\x88\x5b\x87\xa1\x43\xa6\x6e\xd8\x7c\x37\x86\xf7\x93\xc1\x21\x6a\xff\x09\x00\x00\xff\xff\x19\x16\x18\xb8\x7d\x32\x00\x00")

func presetsFilesCisFoundationsPoliciesYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesCisFoundationsPoliciesYml,
		"presets-files/cis-foundations/policies.yml",
	)
}

func presetsFilesCisFoundationsPoliciesYml() (*asset, error) {
	bytes, err := presetsFilesCisFoundationsPoliciesYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/cis-foundations/policies.yml", size: 12925, mode: os.FileMode(420), modTime: time.Unix(1535407610, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _presetsFilesKmsPlaybookYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x3c\xcb\x31\x0e\xc3\x20\x14\x03\xd0\x9d\x53\x58\xec\xa4\x3b\x6b\xc6\x28\x4b\x6f\x40\x89\x2b\x21\x01\x3f\xfa\x9f\x0c\xb9\x7d\x15\xb5\xcd\x66\xcb\xcf\x21\x04\xb7\x4b\x2d\xb9\xd0\x22\xa6\xc7\x3f\x4f\x67\xab\xce\xed\x35\x9d\x16\x1d\x80\x80\x9e\x1a\x23\xfc\xbc\x2e\x78\xca\x48\xa3\x48\xf7\xd7\x02\xdc\xff\x6f\xbd\xb0\x67\xb7\x43\x09\xfd\x49\xbc\x45\x91\x0f\x1b\xd2\xa8\xc8\xca\x34\xb8\x61\x5e\x17\x43\x31\xb0\xa7\x57\xe5\xe6\x3f\x01\x00\x00\xff\xff\x3a\x5c\x69\xfc\x8d\x00\x00\x00")

func presetsFilesKmsPlaybookYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesKmsPlaybookYml,
		"presets-files/kms/playbook.yml",
	)
}

func presetsFilesKmsPlaybookYml() (*asset, error) {
	bytes, err := presetsFilesKmsPlaybookYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/kms/playbook.yml", size: 141, mode: os.FileMode(420), modTime: time.Unix(1535407437, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _presetsFilesKmsPoliciesYml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x6c\x8e\x3b\x6a\x03\x41\x10\x44\xf3\x3d\x45\x31\xf9\x5e\x60\x52\xe1\x68\x51\xe2\x1b\xb4\x67\x6b\x4d\xe3\xf9\x98\xee\x1e\xc1\xde\xde\x48\x56\x60\xb0\xd2\x82\x57\xef\xad\xeb\xba\x7c\x8f\xaa\x45\xe9\x79\x01\x56\x74\x69\xcc\x48\xec\x3e\x8d\xb0\x11\x12\x3a\x3a\x8e\x61\x28\xd3\x63\x34\x1a\x8a\x51\x82\x3b\x2e\xd7\xcd\xa1\x0e\x76\xf9\xa8\xdc\xd3\x02\x00\xce\x1b\x4d\xe3\xcc\x48\x8d\xbb\xce\xf6\x3b\x1b\x7d\x4c\x2b\xcc\xf8\x6a\x9e\x37\x9e\x8f\xf5\xd0\x1a\xb4\x87\xfa\x2e\x2f\xa6\x41\xd3\xd1\x33\xd2\xc6\xf3\xfd\x69\x7f\xfb\xfb\x0f\xdc\xa4\xce\x7b\xe3\x21\xd5\x99\x5e\xa0\x97\x67\xe8\x55\xba\x7c\xfe\xe7\xc2\x26\xd3\x4f\x00\x00\x00\xff\xff\xda\x19\xed\x21\xfa\x00\x00\x00")

func presetsFilesKmsPoliciesYmlBytes() ([]byte, error) {
	return bindataRead(
		_presetsFilesKmsPoliciesYml,
		"presets-files/kms/policies.yml",
	)
}

func presetsFilesKmsPoliciesYml() (*asset, error) {
	bytes, err := presetsFilesKmsPoliciesYmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "presets-files/kms/policies.yml", size: 250, mode: os.FileMode(420), modTime: time.Unix(1535383325, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"presets-files/aws/playbook.yml": presetsFilesAwsPlaybookYml,
	"presets-files/aws/policies.yml": presetsFilesAwsPoliciesYml,
	"presets-files/cis-foundations/playbook.yml": presetsFilesCisFoundationsPlaybookYml,
	"presets-files/cis-foundations/policies.yml": presetsFilesCisFoundationsPoliciesYml,
	"presets-files/kms/playbook.yml": presetsFilesKmsPlaybookYml,
	"presets-files/kms/policies.yml": presetsFilesKmsPoliciesYml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"presets-files": &bintree{nil, map[string]*bintree{
		"aws": &bintree{nil, map[string]*bintree{
			"playbook.yml": &bintree{presetsFilesAwsPlaybookYml, map[string]*bintree{}},
			"policies.yml": &bintree{presetsFilesAwsPoliciesYml, map[string]*bintree{}},
		}},
		"cis-foundations": &bintree{nil, map[string]*bintree{
			"playbook.yml": &bintree{presetsFilesCisFoundationsPlaybookYml, map[string]*bintree{}},
			"policies.yml": &bintree{presetsFilesCisFoundationsPoliciesYml, map[string]*bintree{}},
		}},
		"kms": &bintree{nil, map[string]*bintree{
			"playbook.yml": &bintree{presetsFilesKmsPlaybookYml, map[string]*bintree{}},
			"policies.yml": &bintree{presetsFilesKmsPoliciesYml, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

