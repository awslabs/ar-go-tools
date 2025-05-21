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
	"go/token"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/analysis/taint"
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
			Platform:   *flags.Platform,
			Out:        *flags.Out,
		},
		maxDepth: *maxDepth,
		dryRun:   *dryRun,
	}, nil
}

// Run runs the taint analysis with flags.
func Run(flags Flags) error {
	cfg, err := tools.LoadConfig(flags.CommonFlags, false)
	if err != nil {
		return err
	}
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Infof(formatutil.Faint("Argot taint tool - " + analysis.Version))
	// Override config parameters with command-line parameters
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
		Platform:    flags.Platform,
		Tool:        config.TaintTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get taint targets: %s", err)
	}
	// Loop over every target of the taint analysis
	for targetName, target := range actualTargets {
		targetHasFlows, report, err := runTarget(cfg, targetName, target, flags)
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
	targetInfo config.TargetInfo,
	flags Flags,
) (bool, *config.ReportInfo, error) {
	var err error
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		Platform:      targetInfo.Platform,
		ApplyRewrites: true,
	}
	// Starting the analysis
	c := config.NewState(cfg, targetName, targetInfo.Patterns, loadOptions)
	c.Logger.PushContext(formatutil.Faint(targetName))
	defer c.Logger.PopContext()
	c.Logger.Infof("Taint analysis of target \"%s\" = %v", targetName, targetInfo.Patterns)
	var actual result.Result[config.State]
	if targetInfo.UseProgramTransforms && len(targetInfo.ReflectValueCallInstances) >= 1 {
		c.Logger.Infof("Reflect value call instances specified. Tool supports only 1 for now, will use the first.")
		// TODO: handle more rewrites later
		actual = statefulrewrite.StatefulRewritesOverlayTransform(c,
			statefulrewrite.StatefulRewritesOverlayTransformSpec{ReflectValueCallInstanceCid: targetInfo.ReflectValueCallInstances[0]})
	} else {
		actual = result.Ok(c)
	}
	df, err := result.Bind(
		result.Bind(
			result.Bind(
				actual,
				loadprogram.NewState),
			ptr.NewState),
		dataflow.NewState).Value()
	if err != nil {
		return false, nil, fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	return RunTaint(targetName, flags.CommonFlags, df)
}

// RunTaint runs the taint analysis on the dataflow state
func RunTaint(targetName string, flags tools.CommonFlags, df *dataflow.State) (bool, *config.ReportInfo, error) {
	start := time.Now()
	analysisResult, err := taint.Analyze(df, taint.AnalysisReqs{
		Tag: flags.Tag,
	})
	duration := time.Since(start)
	if err != nil {
		if analysisResult.State != nil {
			for _, err := range analysisResult.State.Report.CheckError() {
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
	analysisResult.State.Logger.Infof("")
	analysisResult.State.Logger.Infof("Taint analysis took %3.4f s", duration.Seconds())
	analysisResult.State.Logger.Infof("")
	if len(analysisResult.TaintFlows.Sinks) == 0 {
		analysisResult.State.Logger.Infof(
			"%sRESULT:\n\t\t%s",
			targetStr,
			formatutil.Green("No taint flows detected ✓")) // safe %s
	} else {
		analysisResult.State.Logger.Errorf(
			"%sRESULT:\n\t\t%s",
			targetStr,
			formatutil.Red("Taint flows detected!")) // safe %s
	}
	if len(analysisResult.TaintFlows.Escapes) > 0 {
		analysisResult.State.Logger.Errorf(
			"%sESCAPE ANALYSIS RESULT:\n\t\t%s",
			targetStr,
			formatutil.Red("Tainted data escapes origin thread!")) // safe %s

	} else if df.Config.UseEscapeAnalysis {
		analysisResult.State.Logger.Infof(
			"%sESCAPE ANALYSIS RESULT:\n\t\t%s",
			targetStr,
			formatutil.Green("Tainted data does not escape ✓")) // safe %s
	}

	LogResult(df.Program, analysisResult)
	analysisResult.State.Logger.Infof(strings.Repeat("*", 80))
	// If some taint flows have been found, or some taint flow escapes, the analysis should return an error.
	// Scripts that use the taint analysis can then rely on the boolean fail/success state of the analysis terminating.
	return len(analysisResult.TaintFlows.Sinks) > 0 || len(analysisResult.TaintFlows.Escapes) > 0, analysisResult.State.Report, nil
}

// LogResult logs the taint analysis result
func LogResult(
	program *ssa.Program, result taint.AnalysisResult) {
	seenPairs := map[struct {
		origin token.Position
		dest   token.Position
	}]bool{}
	// Prints location of sinks and sources in the SSA
	for sink, sources := range result.TaintFlows.Sinks {
		for source := range sources {
			sourceInstr := source.Instr
			sinkInstr := sink.Instr
			sourcePos := program.Fset.File(sourceInstr.Pos()).Position(sourceInstr.Pos())
			sinkPos := program.Fset.File(sinkInstr.Pos()).Position(sinkInstr.Pos())
			posPair := struct {
				origin token.Position
				dest   token.Position
			}{origin: sourcePos, dest: sinkPos}
			if seenPairs[posPair] {
				continue
			}
			seenPairs[posPair] = true
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
