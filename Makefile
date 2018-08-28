SOURCE_FILES?=$$(go list ./... | grep -v /vendor/ | grep -v /mocks/)
TEST_PATTERN?=.
TEST_OPTIONS?=-race -v

setup:
	go get -u github.com/pkg/errors
	go get -u github.com/smartystreets/goconvey/convey
	go get -u github.com/urfave/cli
	go get -u github.com/mitchellh/gox
	go get -u gopkg.in/yaml.v2
	go get -u github.com/Knetic/govaluate
	go get -u github.com/segmentio/ksuid
	go get -u github.com/RackSec/srslog
	go get -u github.com/olekukonko/tablewriter
	go get -u github.com/aws/aws-sdk-go
	go get -u github.com/alecthomas/gometalinter
	go get -u golang.org/x/tools/cmd/cover
	go get -u github.com/360EntSecGroup-Skylar/excelize
	go get -u github.com/jteeuwen/go-bindata/...
	gometalinter --install

test:
	echo 'mode: atomic' > coverage.txt && go list ./... | xargs -n1 -I{} sh -c 'go test -v -timeout=600s -covermode=atomic -coverprofile=coverage.tmp {} && tail -n +2 coverage.tmp >> coverage.txt' && rm coverage.tmp


cover: test
	go tool cover -html=coverage.txt

fmt:
	find . -name '*.go' -not -wholename './presets/presets-data.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

critic:
	gocritic check-project .

lint:
	gometalinter -e testing.go -e validation_test.go -e presets-data.go --vendor --disable-all \
		--enable=deadcode \
		--enable=errcheck \
		--enable=gocyclo \
		--enable=gofmt \
		--enable=goimports \
		--enable=golint \
		--enable=gosimple \
		--enable=ineffassign \
		--enable=misspell \
		--enable=unconvert \
		--enable=varcheck \
		--enable=staticcheck \
		--enable=unparam\
		--enable=varcheck \
		--enable=structcheck \
		--enable=vetshadow \
		--deadline=10m \
		./...

ci: lint test

BUILD_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u '+%Y/%m/%d:%H:%M:%S')

data:
	go-bindata -pkg presets -o presets/presets-data.go presets-files/...

build: fmt data
	GOOS=darwin CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_darwin_amd64" cmd/ape/main.go

build-all: fmt data
	GOOS=darwin  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_darwin_amd64"  cmd/ape/main.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_linux_amd64"   cmd/ape/main.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm   go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_linux_arm"     cmd/ape/main.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_linux_arm64"   cmd/ape/main.go
	GOOS=netbsd  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_netbsd_amd64"  cmd/ape/main.go
	GOOS=openbsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_openbsd_amd64" cmd/ape/main.go
	GOOS=freebsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/ape_freebsd_amd64" cmd/ape/main.go

install:
	go install ./cmd/...

bintray:
	curl -X PUT -0 -T .local_dist/ape_darwin_amd64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_darwin_amd64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_linux_amd64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_linux_amd64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_linux_arm -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_linux_arm;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_linux_arm64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_linux_arm64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_netbsd_amd64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_netbsd_amd64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_openbsd_amd64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_openbsd_amd64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -X PUT -0 -T .local_dist/ape_freebsd_amd64 -ujonhadfield:$(BINTRAY_APIKEY) "https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/ape_freebsd_amd64;bt_package=ape;bt_version=$(BUILD_TAG);publish=1"
	curl -XPOST -0 -ujonhadfield:$(BINTRAY_APIKEY) https://api.bintray.com/content/jonhadfield/ape/ape/$(BUILD_TAG)/publish

release: build-all bintray wait-for-publish build-docker release-docker

wait-for-publish:
	sleep 120

build-docker:
	cd docker ; docker build --no-cache -t quay.io/jonhadfield/ape:$(BUILD_TAG) .
	cd docker ; docker tag quay.io/jonhadfield/ape:$(BUILD_TAG) quay.io/jonhadfield/ape:latest

release-docker:
	cd docker ; docker push quay.io/jonhadfield/ape:$(BUILD_TAG)
	cd docker ; docker push quay.io/jonhadfield/ape:latest

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
