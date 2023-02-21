package main

import (
	"flag"
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/refactor"
	"golang.org/x/tools/go/packages"
	"os"
)

func main() {
	flag.Parse()

	config := &packages.Config{
		Mode:  analysis.PkgLoadMode,
		Tests: false,
	}

	// load, parse and type check the given packages
	loadedPackages, err := packages.Load(config, flag.Args()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load packages: %s", err)
		os.Exit(1)
	}
	refactor.AssignUnhandledErrors(loadedPackages)
}
