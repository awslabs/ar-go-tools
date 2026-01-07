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

package cli

import (
	"context"
	"regexp"
	"runtime"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// cmdSummarize runs the intra-procedural analysis.
func cmdSummarize(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : run the intra-procedural analysis. If a function is provided, "+
			"run only\n", o.EscBlue(), CmdSummarizeName, o.EscReset())
		o.Write("\t   on the provided function\n")
		o.Write("\t   This will build dataflow summaries for all specified functions.\n")
		o.Write("\t   -force flag will force summarization and bypass filters on reachable functions.\n")
		return false
	}

	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	isForced := command.Flags["force"]

	// ensure dataflow state
	res := sess.loadDataflowAnalysis(o)
	if res.IsErr() {
		o.WriteErr("Could not load dataflow: %s", res)
		return false
	}
	c := res.Unwrap()

	if len(command.Args) < 1 {
		// Running the intra-procedural analysis on all functions
		o.WriteSuccess("Running intra-procedural analysis on all functions")
		createCounter := 0
		buildCounter := 0

		shouldBuildSummary := func(c *dataflow.State, f *ssa.Function) bool {
			b := isForced || dataflow.ShouldBuildSummary(c, f)
			if b {
				buildCounter++
			}
			createCounter++
			return b
		}
		ctx := context.Background()
		c.RunIntraProceduralPass(ctx, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack: func(state *dataflow.State, node ssa.Node) bool {
				_, ok := dataflow.IsNodeOfInterest(state, node)
				return ok
			},
		})
		o.WriteSuccess("%d summaries created, %d built", createCounter, buildCounter)
	} else {
		// Running the intra-procedural analysis on a single function, if it can be found
		regex, err := regexp.Compile(command.Args[0])
		if err != nil {
			regexErr(o, command.Args[0], err)
			return false
		}
		funcs, err := sess.findFunc(regex)
		if err != nil {
			o.WriteErr("%s", err.Error())
			return false
		}
		o.WriteSuccess("Running intra-procedural analysis on functions matching %s", command.Args[0])

		// Depending on the summaries threshold and the number of matched functions, different filters are used.
		// If len(funcs) > summarizeThreshold, the filter used is similar to the one used in the taint analysis.
		buildCounter := 0

		var shouldBuildSummary func(c *dataflow.State, f *ssa.Function) bool
		if len(funcs) > summarizeThreshold {
			// above a certain threshold, we use the general analysis filters on what to summarize, unless -force has
			// been specified
			shouldBuildSummary = summarizeWithDefaultParams(o, funcs, isForced, &buildCounter)
		} else {
			// below that threshold, all functions that match are summarize.
			// useful for testing.
			shouldBuildSummary = alwaysSummarize(funcs, &buildCounter)
		}

		// Run the analysis with the filter.
		ctx := context.Background()
		c.RunIntraProceduralPass(ctx, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack: func(state *dataflow.State, node ssa.Node) bool {
				_, ok := dataflow.IsNodeOfInterest(state, node)
				return ok
			},
		})
		// Insert the summaries, i.e. only updated the summaries that have been computed and do not discard old ones

		o.WriteSuccess("%d summaries created, %d built.", len(funcs), buildCounter)
		if buildCounter == 0 {
			o.WriteSuccess("The queried functions may not be reachable?")
			o.WriteSuccess("If less than %d functions match the query, then all reachable "+
				"matching functions will be summarized", summarizeThreshold)
		}
	}
	return false
}

func summarizeWithDefaultParams(o Outputter, funcs []*ssa.Function, isForced bool,
	buildCounter *int) func(*dataflow.State, *ssa.Function) bool {
	o.WriteSuccess("(more than %d functions matching, other config-defined filters are in use)",
		summarizeThreshold)
	shouldBuildSummary := func(c *dataflow.State, f *ssa.Function) bool {
		b := isForced || (!summaries.IsStdFunction(f) &&
			summaries.IsUserDefinedFunction(f) &&
			funcutil.Contains(funcs, f) &&
			!c.HasExternalContractSummary(f))
		if b {
			*buildCounter++
		}
		return b
	}
	return shouldBuildSummary
}

func alwaysSummarize(funcs []*ssa.Function, buildCounter *int) func(*dataflow.State, *ssa.Function) bool {
	shouldBuildSummary := func(_ *dataflow.State, f *ssa.Function) bool {
		b := funcutil.Contains(funcs, f)
		if b {
			*buildCounter++
		}
		return b
	}
	return shouldBuildSummary
}
