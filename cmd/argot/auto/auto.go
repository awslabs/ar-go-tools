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

package auto

import (
	"fmt"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/backtrace"
	"github.com/awslabs/ar-go-tools/cmd/argot/syntactic"
	"github.com/awslabs/ar-go-tools/cmd/argot/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

const usage = ` Perform taint analysis on your packages.
Usage:
  argot taint [options] [package path(s)]
Examples:
  % argot taint -config config.yaml package...
`

// Flags represents the parsed flags for the taint analysis.
type Flags struct {
	tools.CommonFlags
	maxDepth int
	dryRun   bool
}

// NewFlags returns the parsed flags for the taint analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("taint")
	maxDepth := flags.FlagSet.Int("unsafe-df-max-depth", -1, "override dataflow max depth in config: unsafe!")
	dryRun := flags.FlagSet.Bool("dry-run", false, "analysis dry-run: only identify code locations")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command taint with args %v: %v", args, err)
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
			Tag:        *flags.Tag,
			Targets:    *flags.Targets,
		},
		maxDepth: *maxDepth,
		dryRun:   *dryRun,
	}, nil
}

// Run runs the taint analysis with flags.
func Run(flags Flags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return err
	}
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Infof(formatutil.Faint("Argot taint tool - " + analysis.Version))
	// Override config parameters with command-line parameters
	if flags.Verbose {
		tmpLogger.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		tmpLogger = config.NewLogGroup(cfg)
	}
	if flags.maxDepth > 0 {
		cfg.UnsafeMaxDepth = flags.maxDepth
		tmpLogger.Warnf("%s %d\n", "UNSAFE config max data-flow depth set to: %s", flags.maxDepth)
	}
	if flags.dryRun {
		tmpLogger.Infof("dry-run command line flag sets on demand summarization to true")
		cfg.SummarizeOnDemand = true
	}
	if flags.Tag != "" {
		tmpLogger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}
	if flags.Targets != "" {
		tmpLogger.Infof("target specified on command-line, will analyze only for problems with targets in \"%s\"",
			flags.Targets)
	}

	hasFlows := false
	overallReport := config.NewReport()

	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.AutoTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get targets: %s", err)
	}
	// Loop over every target and run the analyses
	for targetName, targetFiles := range actualTargets {

		targetHasFlows, report, err := runTarget(cfg, targetName, targetFiles, flags)
		hasFlows = targetHasFlows || hasFlows
		if err != nil {
			return err
		}
		overallReport.Merge(report)
	}

	overallReport.Dump(config.ConfiguredLogger{Config: cfg, Logger: tmpLogger})
	if hasFlows {
		return fmt.Errorf("argot found problems, inspect logs for more information")
	}
	return nil
}

func runTarget(
	cfg *config.Config,
	targetName string,
	targetFiles []string,
	flags Flags,
) (bool, *config.ReportInfo, error) {
	reportForTarget := config.NewReport()
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	// Starting the analysis
	start := time.Now()
	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	c.Logger.Infof("Analyzing target \"%s\" = %v", targetName, targetFiles)
	c.Logger.PushContext(formatutil.Faint(targetName))
	defer c.Logger.PopContext()
	ptrState, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	if err != nil {
		return false, nil, fmt.Errorf("failed to initialize pointer state: %s", err)
	}
	// Run Syntactic analyses
	syntacticHasFindings, syntacticReport, err := syntactic.RunSyntactic(targetName, ptrState)
	if err != nil {
		c.Logger.Errorf("Error running syntactic analysis on %s: %s", targetName, err)
	}
	reportForTarget.Merge(syntacticReport)
	// Build dataflow state
	df, err := dataflow.NewState(ptrState).Value()
	if err != nil {
		return false, nil, fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	// Run taint analyses
	taintHasFindings, taintReport, err := taint.RunTaint(targetName, flags.CommonFlags, df, start)
	if err != nil {
		c.Logger.Errorf("Error running taint analysis on %s: %s", targetName, err)
	}
	reportForTarget.Merge(taintReport)
	// Run backtrace analyses
	backtraceHasFindings, backtraceReport, err := backtrace.RunBacktrace(flags.CommonFlags, df, start)
	if err != nil {
		c.Logger.Errorf("Error runnning backtrace analysis on %s: %s", targetName, err)
	}
	reportForTarget.Merge(backtraceReport)
	return syntacticHasFindings || backtraceHasFindings || taintHasFindings, reportForTarget, nil
}
