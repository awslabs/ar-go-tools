
#BUILDFILE_PATH := ./build/private/bgo_exports.makefile
#ifneq ("$(wildcard $(BUILDFILE_PATH))","")
#	include ${BUILDFILE_PATH}
#endif
# Install deadcode with:    go install golang.org/x/tools/cmd/deadcode@latest
# Install gocyclo with:     go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
# Install ineffassign with: go install github.com/gordonklaus/ineffassign@latest
# Install golint with:      go install golang.org/x/lint/golint@latest
# Install nilaway with:     go install go.uber.org/nilaway/cmd/nilaway@latest

all: setup-precommit lint argot-build racerg-build test

install: argot-install

lint: **/*.go
	deadcode -test -filter ar-go-tools/analysis ./...
	go vet ./...
	gocyclo -ignore "test|internal/pointer|internal/typeparams" -over 15 .
	ineffassign ./...
	nilaway --test=false ./cmd/argot/...
	golint -set_exit_status -min_confidence 0.9 ./...

test: **/*.go
	go clean -testcache
	go test ./...

argot-build: go.mod cmd/argot/**/*.go
	go build -o bin/argot ./cmd/argot/main.go

argot-install:
	go install github.com/awslabs/ar-go-tools/cmd/argot

racerg-build: go.mod cmd/racerg/*.go
	go build -o bin/racerg cmd/racerg/*.go

build: argot-build racerg-build

setup-precommit:
	cp ./copyrights.sh .git/hooks/pre-commit

clean:
	rm -rf bin
	find . -name "*-report" | xargs rm -rf

release: all
