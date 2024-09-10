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
	"log"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

const usage = ` Perform taint analysis on your packages.
Usage:
  argot taint [options] <package path(s)>
Examples:
  % argot taint -config config.yaml package...
`

// Flags represents the parsed flags for the taint analysis.
type Flags struct {
	tools.CommonFlags
	maxDepth int
}

// NewFlags returns the parsed flags for the taint analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("taint")
	maxDepth := flags.FlagSet.Int("unsafe-df-max-depth", -1, "override dataflow max depth in config: unsafe!")
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
		},
		maxDepth: *maxDepth,
	}, nil
}

// Run runs the taint analysis with flags.
func Run(flags Flags) error {
	logger := log.New(os.Stdout, "", log.Flags())

	taintConfig, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return err
	}

	// Override config parameters with command-line parameters
	if flags.Verbose {
		taintConfig.LogLevel = int(config.DebugLevel)
	}
	if flags.maxDepth > 0 {
		taintConfig.UnsafeMaxDepth = flags.maxDepth
		logger.Printf("%s %d\n", formatutil.Red("[WARNING] UNSAFE config max data-flow depth set to:"), flags.maxDepth)
	}

	logger.Printf(formatutil.Faint("Argot taint tool - " + analysis.Version))
	logger.Printf(formatutil.Faint("Reading sources") + "\n")

	buildMode := ssa.InstantiateGenerics
	program, pkgs, err := analysis.LoadProgram(nil, "", buildMode, flags.WithTest, flags.FlagSet.Args())
	if err != nil {
		return fmt.Errorf("could not load program: %v", err)
	}

	start := time.Now()
	result, err := taint.Analyze(taintConfig, program, pkgs)
	duration := time.Since(start)
	if err != nil {
		if result.State != nil {
			for _, err := range result.State.CheckError() {
				fmt.Fprintf(os.Stderr, "\terror: %v\n", err)
			}
		}
		return fmt.Errorf("taint analysis failed: %v", err)
	}
	result.State.Logger.Infof("")
	result.State.Logger.Infof(strings.Repeat("*", 80))
	result.State.Logger.Infof("Analysis took %3.4f s", duration.Seconds())
	result.State.Logger.Infof("")
	if len(result.TaintFlows.Sinks) == 0 {
		result.State.Logger.Infof(
			"RESULT:\n\t\t%s", formatutil.Green("No taint flows detected ✓")) // safe %s
	} else {
		result.State.Logger.Errorf(
			"RESULT:\n\t\t%s", formatutil.Red("Taint flows detected!")) // safe %s
	}
	if len(result.TaintFlows.Escapes) > 0 {
		result.State.Logger.Errorf(
			"ESCAPE ANALYSIS RESULT:\n\t\t%s", formatutil.Red("Tainted data escapes origin thread!")) // safe %s

	} else if taintConfig.UseEscapeAnalysis {
		result.State.Logger.Infof(
			"ESCAPE ANALYSIS RESULT:\n\t\t%s", formatutil.Green("Tainted data does not escape ✓")) // safe %s
	}

	Report(program, result)

	return nil
}

// Report logs the taint analysis result
func Report(program *ssa.Program, result taint.AnalysisResult) {
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
	for escape, sources := range result.TaintFlows.Escapes {
		for source := range sources {
			sourcePos := program.Fset.File(source.Pos()).Position(source.Pos())
			escapePos := program.Fset.File(escape.Pos()).Position(escape.Pos())
			result.State.Logger.Errorf(
				"%s in function %q:\n\tSink:   [SSA] %q\n\t\t[POSITION] %s\n\tSource: [SSA] %q\n\t\t[POSITION] %s\n",
				formatutil.Yellow("Data escapes thread"),
				escape.Parent().Name(),
				formatutil.SanitizeRepr(escape),
				escapePos.String(), // safe %s (position string)
				formatutil.SanitizeRepr(source),
				sourcePos.String(), // safe %s (position string)
			)
		}
	}
}
