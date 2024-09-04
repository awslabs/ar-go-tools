// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"go/build"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/reachability"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag       = false
	excludeMain    = false
	excludeInit    = false
	mode           = ssa.InstantiateGenerics
	configFilename = ""
)

func init() {
	flag.StringVar(&configFilename, "config", "", "configuration file")
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.BoolVar(&excludeMain, "nomain", false, "exclude main() as a starting point")
	flag.BoolVar(&excludeInit, "noinit", false, "exclude init() as a starting point")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  reachability package...
  reachability source.go
  reachability source1.go source2.go

prefix with GOOS and/or GOARCH to analyze a different architecture:
  GOOS=windows GOARCH=amd64 reachability agent/agent.go agent/agent_parser.go agent/agent_windows.go

Use the -help flag to display the options.

Examples:
% reachability hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "reachability: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {

	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	var err error
	var cfg *config.Config
	if configFilename == "" {
		cfg = config.NewDefault()
	} else {
		cfg, err = config.LoadFromFiles(configFilename)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %s", configFilename, err)
		}
	}
	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")
	state, err := analysis.LoadAnalyzerState(nil, "", mode, flag.Args(), cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer state: %s", err)
	}

	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	reachability.ReachableFunctionsAnalysis(state, excludeMain, excludeInit, jsonFlag)

	return nil
}
