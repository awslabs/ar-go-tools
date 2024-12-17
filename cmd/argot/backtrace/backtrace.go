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
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// Usage for CLI
const Usage = `Find all the backwards data flows from a program point.
Usage:
  argot backtrace [options] <package path(s)>`

// Run runs the backtrace analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags, false)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Infof(formatutil.Faint("Argot backtrace tool - " + analysis.Version))

	if flags.Tag != "" {
		tmpLogger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}
	if flags.Targets != "" {
		tmpLogger.Infof("target specified on command-line, will analyze only for problems with targets in \"%s\"",
			flags.Targets)
	}

	overallReport := config.NewReport()
	foundTraces := false

	// Loop over every target of the taint analysis
	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.BacktraceTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get backtrace targets: %s", err)
	}
	for targetName, target := range actualTargets {
		start := time.Now()
		loadOptions := config.LoadOptions{
			PackageConfig: nil,
			BuildMode:     ssa.InstantiateGenerics,
			LoadTests:     flags.WithTest,
			Platform:      target.Platform,
			ApplyRewrites: true,
		}

		c := config.NewState(cfg, targetName, target.Files, loadOptions)
		c.Logger.Infof("Backtrace analysis of target \"%s\" = %v", targetName, target.Files)
		ptrState := result.Bind(loadprogram.NewState(c), ptr.NewState) // build pointer analysis info
		state, err := result.Bind(ptrState, dataflow.NewState).Value()
		if err != nil {
			return fmt.Errorf("loading failed: %v", err)
		}
		foundNewTraces, report, err2 := RunBacktrace(flags, state, start)
		overallReport.Merge(report)
		foundTraces = foundTraces || foundNewTraces
		if err2 != nil {
			return err2
		}
	}
	overallReport.Dump(config.ConfiguredLogger{Config: cfg, Logger: tmpLogger})
	if foundTraces {
		return fmt.Errorf("backtrace analysis found traces, inspect logs for more information")
	}
	return nil
}

// RunBacktrace runs the backtrace analysis on the state
func RunBacktrace(flags tools.CommonFlags, state *dataflow.State, start time.Time) (bool, *config.ReportInfo, error) {
	foundTraces := false
	analysisResult, err := backtrace.Analyze(state, backtrace.AnalysisReqs{
		Tag: flags.Tag,
	})
	if err != nil {
		return false, nil, fmt.Errorf("analysis failed: %v", err)
	}
	duration := time.Since(start)
	state.Logger.Infof("")
	state.Logger.Infof("-%s", strings.Repeat("*", 80))
	state.Logger.Infof("Analysis took %3.4f s\n", duration.Seconds())
	if len(analysisResult.Traces) > 0 {
		foundTraces = true
		state.Logger.Errorf("Found traces for %d slicing problems\n", len(analysisResult.Traces))
	}
	return foundTraces, state.Report, nil
}
