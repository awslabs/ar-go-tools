// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	staticcommands "github.com/awslabs/argot/analysis/static-commands"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(staticcommands.Analyzer)
}
