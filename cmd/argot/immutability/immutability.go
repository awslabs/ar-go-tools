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

// Package immutability implements the front-end to the immutability analysis.
package immutability

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/immutability"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// Usage for CLI
const Usage = `Perform an immutability analysis on your packages.
Usage:
  argot immutability [options] <package path(s)>`

// Run runs the backtrace analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	logger := config.NewLogGroup(cfg)
	logger.Infof(formatutil.Faint("Argot immutability tool - " + analysis.Version))

	// Override config parameters with command-line parameters
	if flags.Verbose {
		logger.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		logger = config.NewLogGroup(cfg)
	}
	overallReport := config.NewReport()
	for targetName, targetFiles := range tools.GetTargets(flags.FlagSet.Args(), cfg, "immutability") {
		logger.Infof("Reading immutability analysis entrypoints")
		loadOptions := analysis.LoadProgramOptions{
			PackageConfig: nil,
			BuildMode:     ssa.InstantiateGenerics,
			LoadTests:     flags.WithTest,
			ApplyRewrites: true,
		}
		program, pkgs, err := analysis.LoadProgram(loadOptions, targetFiles)
		if err != nil {
			return fmt.Errorf("%s could not load program: %v", targetName, err)
		}

		start := time.Now()
		state, err := dataflow.NewAnalyzerState(program, pkgs, logger, cfg, []func(*dataflow.AnalyzerState){
			func(s *dataflow.AnalyzerState) {
				s.PopulatePointersVerbose(summaries.IsUserDefinedFunction)
			},
		})
		state.Target = targetName
		if err != nil {
			return fmt.Errorf("failed to load state: %s", err)
		}
		result, err := immutability.Analyze(state)
		if err != nil {
			return fmt.Errorf("analysis failed: %v", err)
		}
		duration := time.Since(start)
		overallReport.Merge(state.Report)
		logger.Infof("")
		logger.Infof("-%s", strings.Repeat("*", 80))
		logger.Infof("Analysis took %3.4f s\n", duration.Seconds())
		if len(result.Modifications) == 0 {
			logger.Infof(
				"RESULT:\n\t\t%s", formatutil.Red("No immutability entrypoints detected")) // safe %s
			os.Exit(1)
		} else {
			logger.Infof("RESULT:\n")
		}

		Report(logger, program, result)
	}
	overallReport.Dump(logger, cfg)
	return nil
}

// Report logs the analysis result.
func Report(logger *config.LogGroup, program *ssa.Program, result immutability.AnalysisResult) {
	// Prints location of modifications in the SSA
	fail := false
	for entry, mods := range result.Modifications {
		entryVal := entry.Val
		entryPos := entry.Pos
		msg := formatutil.Green("No writes to source memory detected")
		if len(mods.Writes) > 0 {
			msg = formatutil.Red("Source memory has been modified")
			fail = true
		}
		logger.Infof(
			"%s of arg %s of call %s in %s: [SSA] %s at %s\n",
			msg,
			entry.Val.Name(),
			entry.Call.String(),
			entry.Val.Parent().String(),
			formatutil.SanitizeRepr(entryVal),
			entryPos.String()) // safe %s (position string)
		for instr := range mods.Writes {
			modInstr := instr
			modPos := program.Fset.Position(modInstr.Pos())
			logger.Infof(
				"\tWrite: [SSA] %s in function %s\n\t\t%s\n",
				formatutil.SanitizeRepr(modInstr),
				modInstr.Parent().String(),
				modPos.String(), // safe %s (position string)
			)
		}
		for instr := range mods.Allocs {
			modInstr := instr
			modPos := program.Fset.Position(modInstr.Pos())
			logger.Infof(
				"\tAllocation: [SSA] %s in function %s\n\t\t%s\n",
				formatutil.SanitizeRepr(modInstr),
				modInstr.Parent().String(),
				modPos.String(), // safe %s (position string)
			)
		}
	}

	if fail {
		os.Exit(1)
	}
}
