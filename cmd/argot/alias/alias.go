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

// Package alias implements the frontend for the alias analysis.
package alias

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/alias"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

const Usage = `Perform an alias analysis on your packages.
Usage:
    argot alias [options] <package path(s)>
Examples:
% argot alias -config config.yaml package...
`

// Run runs the alias analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	cfgLog := config.NewLogGroup(cfg)
	cfgLog.Infof(formatutil.Faint("Argot alias tool - " + analysis.Version))

	// Override config parameters with command-line parameters
	if flags.Verbose {
		cfgLog.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		cfgLog = config.NewLogGroup(cfg)
	}
	for targetName, targetFiles := range tools.GetTargets(flags.FlagSet.Args(), cfg, "immutability") {
		cfgLog.Infof("Reading immutability analysis entrypoints for alias analysis")
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
		state, err := dataflow.NewAnalyzerState(program, pkgs, cfgLog, cfg, []func(*dataflow.AnalyzerState){
			func(s *dataflow.AnalyzerState) {
				s.PopulatePointersVerbose(summaries.IsUserDefinedFunction)
			},
		})
		state.Target = targetName
		if err != nil {
			return fmt.Errorf("failed to load state: %s", err)
		}

		results, err := alias.Analyze(state)
		duration := time.Since(start)
		if err != nil {
			return fmt.Errorf("alias analysis failed: %v", err)
		}

		logger := state.Logger
		logger.Infof("")
		logger.Infof("-%s", strings.Repeat("*", 80))
		logger.Infof("Analysis took %3.4f s\n", duration.Seconds())
		if len(results) == 0 {
			logger.Infof(
				"RESULT:\n\t\t%s", formatutil.Green("No potential aliases detected")) // safe %s
		} else {
			logger.Infof(
				"RESULT:\n\t\t%s", formatutil.Red("Potential aliases detected")) // safe %s
			Report(logger, program, results)
			os.Exit(1)
		}
	}

	return nil
}

// Report logs the analysis result
func Report(logger *config.LogGroup, program *ssa.Program, results []alias.AnalysisResult) {
	// Prints location of aliases in the SSA
	for _, result := range results {
		entry := result.Entrypoint
		entryPos := entry.Pos
		for entryArg, aliasedArgs := range result.ArgsAliased {
			logger.Infof(
				"Potential aliases of arg %s of call %s in %s: at %s\n",
				entryArg,
				entry.Call.String(),
				entryArg.Parent().String(),
				entryPos.String()) // safe %s (position string)
			for _, alias := range aliasedArgs {
				logger.Infof("\tmay be aliased by arg %s\n", alias)
			}
		}
	}
}
