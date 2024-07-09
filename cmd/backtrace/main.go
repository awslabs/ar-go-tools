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
	"log"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

var (
	configPath = flag.String("config", "", "Config file path for backtrace analysis")
	verbose    = flag.Bool("verbose", false, "Verbose printing on standard output")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.InstantiateGenerics
)

const usage = `Find the backwards data flow traces from function arguments.
Usage:
    backtrace [options] <package path(s)>
Examples:
% taint -config config.yaml package...
`

func main() {
	var err error
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "", log.Flags())

	cfg := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		cfg, err = config.LoadGlobal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %s\n", *configPath)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return
		}
	}

	// Override config parameters with command-line parameters
	if *verbose {
		cfg.LogLevel = int(config.DebugLevel)
	}

	logger.Printf(formatutil.Faint("Reading backtrace entrypoints") + "\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}

	start := time.Now()
	result, err := backtrace.Analyze(config.NewLogGroup(cfg), cfg, program)
	duration := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analysis failed: %v\n", err)
		return
	}
	logger.Printf("")
	logger.Printf("-%s", strings.Repeat("*", 80))
	logger.Printf("Analysis took %3.4f s\n", duration.Seconds())
	logger.Printf("Found traces for %d entrypoints\n", len(result.Traces))
}
