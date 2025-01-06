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

package taint

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	resultMonad "github.com/awslabs/ar-go-tools/internal/funcutil/result"
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
		Tool:        config.TaintTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get taint targets: %s", err)
	}
	// Loop over every target of the taint analysis
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
		return fmt.Errorf("taint analysis found problems, inspect logs for more information")
	}
	return nil
}

func runTarget(
	cfg *config.Config,
	targetName string,
	targetFiles []string,
	flags Flags,
) (bool, *config.ReportInfo, error) {
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	// Starting the analysis
	start := time.Now()
	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	df, err := resultMonad.Bind(resultMonad.Bind(loadprogram.NewState(c), ptr.NewState), dataflow.NewState).Value()
	if err != nil {
		return false, nil, fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	result, err := taint.Analyze(df, taint.AnalysisReqs{
		Tag: flags.Tag,
	})
	duration := time.Since(start)
	if err != nil {
		if result.State != nil {
			for _, err := range result.State.Report.CheckError() {
				fmt.Fprintf(os.Stderr, "\terror: %v\n", err)
			}
		}
		return false, nil, fmt.Errorf("taint analysis failed: %v", err)
	}

	// Printing final results
	targetStr := ""
	if targetName != "" {
		targetStr = "TARGET " + targetName + " "
	}
	result.State.Logger.Infof("")
	result.State.Logger.Infof(strings.Repeat("*", 80))
	result.State.Logger.Infof("Analysis took %3.4f s", duration.Seconds())
	result.State.Logger.Infof("")
	if len(result.TaintFlows.Sinks) == 0 {
		result.State.Logger.Infof(
			"%sRESULT:\n\t\t%s",
			targetStr,
			formatutil.Green("No taint flows detected ✓")) // safe %s
	} else {
		result.State.Logger.Errorf(
			"%sRESULT:\n\t\t%s",
			targetStr,
			formatutil.Red("Taint flows detected!")) // safe %s
	}
	if len(result.TaintFlows.Escapes) > 0 {
		result.State.Logger.Errorf(
			"%sESCAPE ANALYSIS RESULT:\n\t\t%s",
			targetStr,
			formatutil.Red("Tainted data escapes origin thread!")) // safe %s

	} else if cfg.UseEscapeAnalysis {
		result.State.Logger.Infof(
			"%sESCAPE ANALYSIS RESULT:\n\t\t%s",
			targetStr,
			formatutil.Green("Tainted data does not escape ✓")) // safe %s
	}

	LogResult(df.Program, result)
	// If some taint flows have been found, or some taint flow escapes, the analysis should return an error.
	// Scripts that use the taint analysis can then rely on the boolean fail/success state of the analysis terminating.
	return len(result.TaintFlows.Sinks) > 0 || len(result.TaintFlows.Escapes) > 0, result.State.Report, nil
}

// LogResult logs the taint analysis result
func LogResult(
	program *ssa.Program, result taint.AnalysisResult) {
	// Prints location of sinks and sources in the SSA
	for sink, sources := range result.TaintFlows.Sinks {
		for source := range sources {
			sourceInstr := source.Instr
			sinkInstr := sink.Instr
			sourcePos := program.Fset.File(sourceInstr.Pos()).Position(sourceInstr.Pos())
			sinkPos := program.Fset.File(sinkInstr.Pos()).Position(sinkInstr.Pos())
			result.State.Logger.Warnf(
				"%s in function %s:\n\tSource: [SSA] %s\n\t\t%s\n\tSink: [SSA] %s\n\t\t%s\n",
				formatutil.Red("Data from a source has reached a sink"),
				sinkInstr.Parent().Name(),
				formatutil.SanitizeRepr(sourceInstr),
				sourcePos.String(), // safe %s (position string)
				formatutil.SanitizeRepr(sinkInstr),
				sinkPos.String(), // safe %s (position string)
			)
		}
	}

	// Prints location of positions where source data escapes in the SSA
	for source, escapes := range result.TaintFlows.Escapes {
		for escape, rationale := range escapes {
			sourcePos := program.Fset.File(source.Pos()).Position(source.Pos())
			escapePos := program.Fset.File(escape.Pos()).Position(escape.Pos())
			result.State.Logger.Errorf(
				"%s in function %q:\n\tSink:   [SSA] %q\n\t\t[POSITION] %s\n\tLeak:   %q\n\tSource: [SSA] %q\n\t\t[POSITION] %s\n",
				formatutil.Yellow("Data escapes thread"),
				escape.Parent().Name(),
				formatutil.SanitizeRepr(escape),
				escapePos.String(), // safe %s (position string)
				formatutil.Sanitize(rationale.String()),
				formatutil.SanitizeRepr(source),
				sourcePos.String(), // safe %s (position string)
			)
		}
	}
}
