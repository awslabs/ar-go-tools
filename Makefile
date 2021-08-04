
BUILDFILE_PATH := ./build/private/bgo_exports.makefile
ifneq ("$(wildcard $(BUILDFILE_PATH))","")
	include ${BUILDFILE_PATH}
endif

gozer: go.mod cmd/gozer/*.go
	go build -o bin/gozer ./cmd/gozer

all: gozer

release: all
