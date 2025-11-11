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

package check

import (
	"fmt"
	"runtime"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

// Usage for CLI
const usage = `Check the soundness of the data flow summaries in a summary file.
See the "Dataflow Specifications" section in the taint analysis documentation
for information on how to write the summary file.

Usage:
  argot check [options] --summary <summary file path> <package path(s)>`

// Flags represents the parsed flags for the taint analysis.
type Flags struct {
	tools.CommonFlags
	summaryPath string
}

// NewFlags returns the parsed flags for the data flow summary checking analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags(config.CheckTool)
	summaryPath := flags.FlagSet.String("summary", "", "path to data flow summary file")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command check with args %v: %v", args, err)
	}
	if summaryPath == nil || *summaryPath == "" {
		return Flags{}, fmt.Errorf("must specify a data flow summary file")
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
		summaryPath: *summaryPath,
	}, nil
}

// Run runs the data flow summary checking analysis.
func Run(flags Flags) error {
	cfg := config.NewDefault()
	cfg.DataflowProblems.SummarizeOnDemand = true
	cfg.LogLevel = int(config.DebugLevel)
	cfg.Options.UnsafeMaxDepth = -1
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Info(formatutil.Faint("Argot check tool - " + analysis.Version))

	parsedSummaries, err := summaries.ParseSummariesFile(flags.summaryPath)
	if err != nil {
		return fmt.Errorf("failed to parse summaries file %s: %v", flags.summaryPath, err)
	}

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		Platform:      flags.Platform,
		ApplyRewrites: false,
	}
	c := config.NewState(cfg, flags.summaryPath, flags.FlagSet.Args(), loadOptions)
	ptrState := result.Bind(
		loadprogram.NewState(c),
		ptr.NewState)
	df, err := result.Bind(
		ptrState,
		dataflow.NewState).Value()
	if err != nil {
		return fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	df.DataFlowContracts = make(map[string]*dataflow.SummaryGraph) // reset data flow contracts
	dataflow.RunIntraProceduralPass(df, runtime.NumCPU(), dataflow.IntraAnalysisParams{
		// Don't build any summaries since we're summarizing on-demand
		ShouldBuildSummary: func(*dataflow.State, *ssa.Function) bool {
			return false
		},
		// No need to track sources, sinks, or synthetic nodes since they don't appear in data flow summaries
		ShouldTrack: func(s *dataflow.State, n ssa.Node) bool {
			return false
		},
	})

	for _, summary := range parsedSummaries {
		targetName := summary.Name()
		c.Logger.PushContext(formatutil.Faint(targetName))
		err := checkSummary(df, summary)
		if err != nil {
			c.Logger.Errorf("failed to check the summary of function %s: %v", targetName, err)
		}
		c.Logger.PopContext()
	}

	return nil
}

func checkSummary(s *dataflow.State, summary summaries.FrontendDataflowSummary) error {
	var f *ssa.Function
	for fn := range s.ReachableFunctions() {
		fname := fn.RelString(nil)
		if fname == summary.Name() {
			f = fn
		}
	}
	if f == nil {
		return fmt.Errorf("could not find function (is it reachable from main?)")
	}

	graph := dataflow.NewSummaryGraph(s, f,
		dataflow.GetUniqueFunctionID(), func(*dataflow.State, ssa.Node) bool { return true }, nil)
	_, isInterface := summary.(summaries.IfaceMethodFlowSummary)
	if isInterface {
		panic("analysis doesn't handle interfaces yet")
	}

	// graph.PopulateGraphFromSummary(summary.Summary(), isInterface)

	graph.IsInterfaceContract = false
	graph.IsPreSummarized = false
	graph.Constructed = false
	_, err := dataflow.RunIntraProcedural(s, graph)
	if err != nil {
		return fmt.Errorf("failed to run intra-procedural analysis on function")
	}
	// sound := dataflow.IsSummarySound(graph, s.FlowGraph)
	// s.Logger.Infof("data flow summary for function %s is sound: %v", summary.Name(), sound)

	for _, param := range graph.Params {
		v := dataflow.NewFunctionVisitor()
		s.Logger = config.NewLogGroup(&config.Config{
			Options: config.Options{
				LogLevel:    int(config.TraceLevel),
				SilenceWarn: true,
			},
		})
		v.Visit(s, dataflow.NodeWithTrace{Node: param})
	}
	s.FlowGraph.Sync()

	for fn, completeSummary := range s.FlowGraph.Summaries {
		if fn == f {
			completeSummary.PrettyPrint(true, s.Logger.GetDebug().Writer(), nil)
		}
	}

	return nil
}
