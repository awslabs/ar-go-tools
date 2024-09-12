
#BUILDFILE_PATH := ./build/private/bgo_exports.makefile
#ifneq ("$(wildcard $(BUILDFILE_PATH))","")
#	include ${BUILDFILE_PATH}
#endif
# Install deadcode with:    go install golang.org/x/tools/cmd/deadcode@latest
# Install gocyclo with:     go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
# Install ineffassign with: go install github.com/gordonklaus/ineffassign@latest
# Install golint with:      go install golang.org/x/lint/golint@latest

all: lint maypanic statistics reachability dependencies static-commands render taint compare defer packagescan backtrace argot-cli racerg setup-precommit

install: taint_install backtrace_install cli_install

lint: **/*.go
	# deadcode -test -filter ar-go-tools/analysis ./... TODO: re-enable when deadcode is fixed for go1.23
	go vet ./...
	gocyclo -ignore "test|internal/pointer|internal/typeparams" -over 15 .
	ineffassign ./...
	golint -set_exit_status -min_confidence 0.9 ./...

test: **/*.go
	go vet ./...
	go clean -testcache
	go test ./analysis/...

maypanic: go.mod cmd/maypanic/*.go analysis/*.go analysis/reachability/*.go analysis/maypanic/*.go
	go build -o bin/maypanic cmd/maypanic/*.go

dependencies: go.mod cmd/dependencies/*.go analysis/*.go analysis/dependencies/*.go analysis/reachability/*.go
	go build -o bin/dependencies cmd/dependencies/*.go

statistics: go.mod cmd/statistics/*.go analysis/*.go
	go build -o bin/statistics cmd/statistics/*.go

reachability: go.mod cmd/reachability/*.go analysis/*.go analysis/reachability/*.go
	go build -o bin/reachability cmd/reachability/*.go

static-commands: go.mod cmd/static-commands/*.go analysis/*.go analysis/static-commands/*.go
	go build -o bin/static-commands cmd/static-commands/*.go

render: go.mod cmd/render/*.go analysis/*.go
	go build -o bin/render cmd/render/*.go

taint: go.mod cmd/taint/*.go analysis/*.go analysis/taint/*.go
	go build -o bin/taint cmd/taint/*.go

defer: go.mod cmd/defer/*.go analysis/*.go
	go build -o bin/defer cmd/defer/*.go

compare: go.mod cmd/compare/*.go analysis/*.go analysis/reachability/*.go
	go build -o bin/compare cmd/compare/*.go

packagescan: go.mod cmd/packagescan/*.go analysis/*.go
	go build -o bin/packagescan cmd/packagescan/*.go

backtrace: go.mod cmd/backtrace/*.go analysis/*.go analysis/backtrace/*.go
	go build -o bin/backtrace cmd/backtrace/*.go

argot-cli: go.mod cmd/argot-cli/*.go
	go build -o bin/argot-cli cmd/argot-cli/*.go

racerg: go.mod cmd/racerg/*.go
	go build -o bin/racerg cmd/racerg/*.go

taint_install: taint
	go install ./cmd/taint/...

backtrace_install: backtrace
	go install ./cmd/backtrace/...

cli_install: argot-cli
	go install ./cmd/argot-cli

setup-precommit:
	cp ./copyrights.sh .git/hooks/pre-commit

clean:
	rm -rf bin
	find ./testdata -name "*-report" | xargs rm -rf

release: all
