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

package syntactic

import (
	"fmt"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/syntactic/preconditions"
	"github.com/awslabs/ar-go-tools/analysis/syntactic/structinit"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// Usage is the usage info for the syntactic analyses.
const Usage = ` Perform syntactic checks on your packages.
Usage:
  argot syntactic [options] <package path(s)>
Examples:
  % argot syntactic -config config.yaml package...
`

// Run runs the syntactic analyses.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags, false)
	if err != nil {
		return err
	}
	tmpLogger := config.NewLogGroup(cfg)

	if len(cfg.SyntacticProblems.StructInitProblems) == 0 && len(cfg.SyntacticProblems.CondCheckSpecs) == 0 {
		tmpLogger.Warnf("No syntactic problems in config file.")
		return nil
	}

	if flags.Tag != "" {
		tmpLogger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}

	if flags.Targets != "" {
		tmpLogger.Infof("target specified on command-line, will analyze only for problems with targets in \"%s\"",
			flags.Targets)
	}

	failCount := 0
	overallReport := config.NewReport()

	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.SyntacticTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get syntactic targets: %s", err)
	}
	if len(actualTargets) == 0 {
		tmpLogger.Warnf("No syntactic targets found.")
		return nil
	}
	for targetName, target := range actualTargets {
		_, report, err := runTarget(cfg, targetName, target.Patterns, target.Platform, flags)
		if err != nil {
			tmpLogger.Errorf("Analysis for %s failed: %s", targetName, err)
			failCount += 1
		}
		overallReport.Merge(report)
	}
	overallReport.Dump(config.ConfiguredLogger{Config: cfg, Logger: tmpLogger})
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
) (bool, *config.ReportInfo, error) {
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
		Platform:      targetPlatform,
		PackageConfig: nil,
	}
	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	c.Logger.Infof("Syntactic analysis of target \"%s\" = %v", targetName, targetFiles)
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	if err != nil {
		return false, nil, fmt.Errorf("failed to load target: %v", err)
	}
	// struct analysis
	structAnalysisFailed := false
	if len(cfg.SyntacticProblems.StructInitProblems) > 0 {
		start := time.Now()
		c.Logger.Infof("starting struct init analysis...\n")
		structInitRes, err := structinit.Analyze(state, structinit.AnalysisReqs{Tag: flags.Tag})
		if err != nil {
			return false, nil, fmt.Errorf("struct init analysis error: %v", err)
		}
		var s string
		s, structAnalysisFailed = structinit.FormattedReport(structInitRes)
		c.Logger.Infof("Struct analysis done (%.3f s)", time.Since(start).Seconds())
		c.Logger.Infof(s)
	}
	// condition check analysis
	preconditionAnalysisFailed := false
	if len(cfg.SyntacticProblems.CondCheckSpecs) > 0 {
		start := time.Now()
		c.Logger.Infof("starting precondition analysis...\n")
		precondCheckRes, err := preconditions.Analyze(state, preconditions.AnalysisReqs{Tag: flags.Tag})
		if err != nil {
			return false, nil, fmt.Errorf("precondition analysis error: %v", err)
		}
		var s string
		s, preconditionAnalysisFailed = preconditions.FormattedReport(precondCheckRes)
		c.Logger.Infof("Precondition analysis done (%.3f s)", time.Since(start).Seconds())
		c.Logger.Infof(s)
	}
	// Failure for all syntactic analyses
	if structAnalysisFailed || preconditionAnalysisFailed {
		return false,
			state.Report,
			fmt.Errorf("syntactic analysis found problems, inspect logs for more information")
	}
	return false, state.Report, nil
}
