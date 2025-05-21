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

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/immutability"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// Usage for CLI
const Usage = `Perform an immutability analysis on your packages.
Usage:
  argot immutability [options] <package path(s)>`

// Run runs the analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags, false)
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

	if len(cfg.ImmutabilityProblems) == 0 {
		logger.Warnf("No immutability problems in config file.")
		return nil
	}

	if flags.Tag != "" {
		logger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}

	failCount := 0
	overallReport := config.NewReport()
	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.ImmutabilityTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get immutability targets: %s", err)
	}
	for targetName, target := range actualTargets {
		report, err := runTarget(cfg, targetName, target.Patterns, target.Platform, flags)
		if err != nil {
			logger.Errorf("Analysis for %s failed: %s", targetName, err)
			failCount += 1
		}
		overallReport.Merge(report)
	}
	overallReport.Dump(config.ConfiguredLogger{Config: cfg, Logger: logger})
	if failCount > 0 {
		os.Exit(1)
	}

	return nil
}

func runTarget(
	cfg *config.Config,
	targetName string,
	targetFiles []string,
	targetPlatform string,
	flags tools.CommonFlags,
) (*config.ReportInfo, error) {
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
		Platform:      targetPlatform,
		PackageConfig: nil,
	}
	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	if err != nil {
		return nil, fmt.Errorf("failed to load target: %v", err)
	}
	c.Logger.Infof("starting immutability analysis...\n")
	res, err := immutability.Analyze(state)
	if err != nil {
		return nil, fmt.Errorf("immutability analysis error: %v", err)
	}
	s, failed := immutability.ReportResults(res)
	c.Logger.Infof(s)
	if failed {
		return state.Report, fmt.Errorf("immutability analysis found problems, inspect logs for more information")
	}
	return state.Report, nil
}
