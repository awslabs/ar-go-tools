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

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/alias"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// Usage is the CLI help message.
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
	logger := config.NewLogGroup(cfg)
	logger.Infof(formatutil.Faint("Argot alias tool - " + analysis.Version))

	if len(cfg.ImmutabilityProblems) == 0 {
		logger.Warnf("no immutability problems for alias analysis in config file")
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
		Tool:        config.ImmutabilityTool, // HACK use immutability targets for now
	})
	if err != nil {
		return fmt.Errorf("failed to get alias (immutability) targets: %s", err)
	}
	for targetName, targetFiles := range actualTargets {
		report, err := runTarget(cfg, targetName, targetFiles, flags)
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
	flags tools.CommonFlags,
) (*config.ReportInfo, error) {
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
		Platform:      "",
		PackageConfig: nil,
	}
	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	if err != nil {
		return nil, fmt.Errorf("failed to load target: %v", err)
	}
	c.Logger.Infof("starting alias analysis...\n")
	res, err := alias.Analyze(state)
	if err != nil {
		return nil, fmt.Errorf("alias analysis error: %v", err)
	}
	s, failed := alias.ReportResults(res)
	c.Logger.Infof(s)
	if failed {
		return state.Report, fmt.Errorf("alias analysis found problems, inspect logs for more information")
	}
	return state.Report, nil
}
