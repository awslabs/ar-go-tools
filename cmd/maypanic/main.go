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

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/maypanic"
	"github.com/awslabs/argot/analysis/utils"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag              = false
	mode                  = ssa.BuilderMode(0)
	exclude  excludeFlags = []string{}
)

func (exclude *excludeFlags) String() string {
	return ""
}

func (exclude *excludeFlags) Set(value string) error {
	*exclude = append(*exclude, value)
	return nil
}

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	flag.Var(&exclude, "exclude", "path to exclude from analysis")
}

const usage = `Analyze your Go packages.

Usage:
  maypanic package...
  maypanic source.go

Use the -help flag to display the options.

Examples:
% maypanic hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "maypanic: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {

	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cfg := &packages.Config{
		// packages.LoadSyntax for given files only
		Mode:  packages.LoadAllSyntax,
		Tests: false,
	}

	fmt.Fprintf(os.Stderr, utils.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(cfg, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, utils.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	excludeAbsolute := maypanic.MakeAbsolute(exclude)

	maypanic.MayPanicAnalyzer(program, excludeAbsolute, jsonFlag)

	return nil
}
