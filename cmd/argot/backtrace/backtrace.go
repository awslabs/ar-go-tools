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

// Package backtrace implements the front-end to the backtrace analysis.
package backtrace

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// Usage for CLI
const Usage = `Find all the backwards data flows from a program point.
Usage:
  argot backtrace [options] <package path(s)>`

// Run runs the backtrace analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	logger := log.New(os.Stdout, "", log.Flags())

	// Override config parameters with command-line parameters
	if flags.Verbose {
		cfg.LogLevel = int(config.DebugLevel)
	}

	logger.Printf(formatutil.Faint("Reading backtrace entrypoints") + "\n")

	loadOptions := analysis.LoadProgramOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	program, pkgs, err := analysis.LoadProgram(loadOptions, flags.FlagSet.Args())
	if err != nil {
		return fmt.Errorf("could not load program: %v", err)
	}

	start := time.Now()
	result, err := backtrace.Analyze(config.NewLogGroup(cfg), cfg, program, pkgs)
	if err != nil {
		return fmt.Errorf("analysis failed: %v", err)
	}
	duration := time.Since(start)
	logger.Printf("")
	logger.Printf("-%s", strings.Repeat("*", 80))
	logger.Printf("Analysis took %3.4f s\n", duration.Seconds())
	logger.Printf("Found traces for %d entrypoints\n", len(result.Traces))

	return nil
}
