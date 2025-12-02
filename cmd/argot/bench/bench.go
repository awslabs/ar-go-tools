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

package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"math"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

const Usage = ` Benchmark dataflow summarization on your packages.
Usage:
  argot bench [options] [package path(s)]
Examples:
  % argot bench -config config.yaml package...
`

func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags, false)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	// Make sure there are no summary specs
	cfg.UserSpecs = nil
	// Unset all pre-defined summaries
	summaries.UnsetStdLibSummaries()
	// Hardcode log level for now (TODO make this an option)
	cfg.LogLevel = int(config.TraceLevel)

	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Info(formatutil.Faint("Argot bench tool - " + analysis.Version))

	cfg.SilenceWarn = true
	if cfg.MaxEntrypointContextSize <= 0 {
		tmpLogger.Infof(
			"config does not specify an intra-procedural timeout in dataflow-problems, using default value of %v\n", 5)
		cfg.MaxEntrypointContextSize = 5
	}
	if cfg.DataflowProblems.IntraTimeoutMs <= 0 {
		tmpLogger.Infof(
			"config does not specify an intra-procedural timeout in dataflow-problems, using default value of %v\n",
			defaultIntraTimeout)
		cfg.DataflowProblems.IntraTimeoutMs = int(defaultIntraTimeout.Milliseconds())
	}

	// Loop over every target of the taint analysis
	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.TaintTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get taint targets: %s", err)
	}
	if len(actualTargets) == 0 {
		return fmt.Errorf("no targets to analyze (did you misspell the target?)")
	}

	for targetName, target := range actualTargets {
		loadOptions := config.LoadOptions{
			PackageConfig: nil,
			BuildMode:     ssa.InstantiateGenerics,
			LoadTests:     flags.WithTest,
			Platform:      target.Platform,
			ApplyRewrites: true,
		}

		c := config.NewState(cfg, targetName, target.Patterns, loadOptions)
		var cfgRes result.Result[config.State]
		if target.UseProgramTransforms && len(target.ReflectValueCallInstances) >= 1 {
			c.Logger.Infof("Reflect value call instances specified. Tool supports only 1 for now, will use the first.")
			// TODO: handle more rewrites later
			cfgRes = statefulrewrite.StatefulRewritesOverlayTransform(c,
				statefulrewrite.StatefulRewritesOverlayTransformSpec{ReflectValueCallInstanceCid: target.ReflectValueCallInstances[0]})
		} else {
			cfgRes = result.Ok(c)
		}
		c.Logger.Infof("Benchmark analysis of taint target \"%s\" = %v", targetName, target.Patterns)
		c.Logger.PushContext(formatutil.Faint(targetName))
		ptrState := result.Bind(result.Bind(cfgRes, loadprogram.NewState), ptr.NewState)
		state, err := result.Bind(ptrState, dataflow.NewState).Value()
		if err != nil {
			return fmt.Errorf("loading failed: %v", err)
		}

		// TODO make ahead-of-time vs on-demand an option
		var fullReport report
		if false {
			incReports := runBenchAll(state)
			fullReport = newReportFromIncomplete(state, incReports)
		} else {
			reports := runBenchDemand(state)
			fullReport = newReport(reports)
		}

		var name string
		if len(targetName) == 0 {
			name = "bench-report.json"
		} else {
			name = fmt.Sprintf("bench-%s-report.json", targetName)
		}
		file, err := os.Create(name)
		if err != nil {
			return fmt.Errorf("failed to create report file: %v", err)
		}
		defer file.Close()
		enc := json.NewEncoder(file)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(fullReport); err != nil {
			return fmt.Errorf("failed to encode report: %v", err)
		}

		c.Logger.Infof("wrote benchmark report to file %s\n", name)
		c.Logger.PopContext()
	}
	return nil
}

const defaultIntraTimeout = 500 * time.Millisecond
const defaultInterTimeout = 30 * time.Second

func runBenchDemand(state *dataflow.State) []funcReport {
	state.Config.DataflowProblems.SummarizeOnDemand = true
	// clear summaries and dataflow contracts to ensure all summaries are computed from scratch
	for f := range state.FlowGraph.Summaries {
		delete(state.FlowGraph.Summaries, f)
	}
	for k := range state.DataFlowContracts {
		delete(state.DataFlowContracts, k)
	}

	numRoutines := max(1, runtime.NumCPU()-1)
	// Only build summaries for non-stdlib functions here
	dataflow.RunIntraProceduralPass(context.Background(), state, numRoutines,
		dataflow.IntraAnalysisParams{
			ShouldBuildSummary: func(*dataflow.State, *ssa.Function) bool {
				// Don't build any summaries: we compute them on-demand
				return false
			},
			// For the intra-procedural pass, all source nodes of all problems are marked
			ShouldTrack: dataflow.IsNodeOfInterest,
		})

	var res []funcReport
	for _, taintSpec := range state.Config.TaintTrackingProblems {
		// Run modified taint analysis
		reports := make(chan funcReport)
		go func() {
			visitor := NewVisitor(&taintSpec, reports)
			ctx, cancel := context.WithTimeout(context.Background(), defaultInterTimeout)
			defer cancel()
			dataflow.RunInterProcedural(ctx, state, visitor, dataflow.ScanningSpec{
				// The entry points are specific to each taint tracking problem (unlike in the intra-procedural pass)
				IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
					return dataflow.IsSourceNode(state, &taintSpec, node)
				},
				MarkCallArgsLikeCall: taintSpec.SourceTaintsArgs,
			})
			close(reports)
		}()

		done := make(chan struct{})
		go func() {
			for report := range reports {
				res = append(res, report)
			}
			done <- struct{}{}
		}()
		// Wait until the current spec is finished before continuing to the next one
		<-done
	}

	return res
}

func runBenchAll(state *dataflow.State) []incompleteFuncReport {
	// clear summaries and dataflow contracts to ensure all summaries are computed from scratch
	for f := range state.FlowGraph.Summaries {
		delete(state.FlowGraph.Summaries, f)
	}
	for k := range state.DataFlowContracts {
		delete(state.DataFlowContracts, k)
	}

	funcs := make([]*ssa.Function, 0, len(state.ReachableFunctions()))
	for f := range state.ReachableFunctions() {
		funcs = append(funcs, f)
	}

	job := func(f *ssa.Function) incompleteFuncReport { return summarize(state, f) }
	numRoutines := int(math.Max(1, float64(runtime.NumCPU()-1)))
	incReports := funcutil.MapParallel(funcs, job, numRoutines)
	if len(incReports) == 0 {
		panic(fmt.Errorf("no reports"))
	}

	// add all summaries (can't be done in parallel because maps are not thread safe)
	for _, report := range incReports {
		state.FlowGraph.Summaries[report.Func] = report.summary
	}

	return incReports
}

func newReportFromIncomplete(state *dataflow.State, incReports []incompleteFuncReport) report {
	// Build inter-procedural graph to populate Callsites
	state.FlowGraph.BuildGraph()

	reports := make([]funcReport, 0, len(incReports))
	for _, report := range incReports {
		r := newFuncReport(state, report)
		reports = append(reports, r)
	}

	return newReport(reports)
}

func newFuncReport(state *dataflow.State, report incompleteFuncReport) funcReport {
	ctxs := firstFiveCallContexts(state, report.Func)
	return funcReport{
		Name:        report.Func.String(),
		Unsoundness: report.Unsoundness,
		IntraTime:   report.IntraTime,
		CallCtxs:    ctxs,
	}
}

func firstFiveCallContexts(state *dataflow.State, f *ssa.Function) []*dataflow.CallStack {
	var res []*dataflow.CallStack
	if len(state.FlowGraph.Summaries) == 0 {
		panic("no summaries")
	}
Loop:
	for _, sm := range state.FlowGraph.Summaries {
		for _, fn2call := range sm.Callees {
			for _, call := range fn2call {
				if call.Callee() == f {
					callStacks := dataflow.GetAllCallingContexts(state, call)
					res = append(res, callStacks...)
					if len(res) >= 5 {
						break Loop
					}
				}
			}
		}
	}

	slices.SortFunc(res, func(a, b *dataflow.CallStack) int {
		return a.Len() - b.Len()
	})

	return res
}

func summarize(state *dataflow.State, f *ssa.Function) incompleteFuncReport {
	timeout := state.Config.DataflowProblems.IntraTimeoutMs
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	intra, err := dataflow.IntraProceduralAnalysis(
		ctx, state, f, true, dataflow.GetUniqueFunctionID(), dataflow.IsNodeOfInterest, nil)
	timedOut := errors.Is(err, context.DeadlineExceeded)
	if err != nil && !timedOut {
		panic(fmt.Errorf("failed to summarize function %s: %v", f.String(), err))
	}

	res := incompleteFuncReport{
		summary: intra.Summary,
		Func:    f,
		Unsoundness: UnsoundnessReport{
			Features: intra.Summary.Unsoundness(),
			TimedOut: timedOut,
		},
		IntraTime: intra.Time,
	}
	return res
}

type report []funcReport

func newReport(reports []funcReport) report {
	// sort report entries from longest time to shortest
	slices.SortFunc(reports, func(a, b funcReport) int {
		return int(b.IntraTime) - int(a.IntraTime)
	})

	return report(reports)
}

type funcReport struct {
	Name        string
	Unsoundness UnsoundnessReport
	IntraTime   time.Duration
	CallCtxs    []*dataflow.CallStack
}

func (r funcReport) MarshalJSON() ([]byte, error) {
	type rawUnsoundFeatures struct {
		Recovers           map[string]bool   `json:"recovers"`
		UnsafeUsages       map[string]string `json:"unsafe-usages"`
		ReflectUsages      map[string]string `json:"reflect-usages"`
		HasUnboundedDefers bool              `json:"has-unbounded-defers"`
	}
	type rawUnsoundness struct {
		Features rawUnsoundFeatures `json:"features"`
		TimedOut bool               `json:"timedOut"`
	}
	type rawFuncReport struct {
		Name         string         `json:"function-name"`
		Unsoundness  rawUnsoundness `json:"unsoundness"`
		IntraTimeMs  int64          `json:"intra-time-ms"`
		CallContexts []string       `json:"call-contexts"`
	}

	callCtxs := make(map[string]struct{})
	for _, callCtx := range r.CallCtxs {
		callCtxs[callCtx.SummaryString()] = struct{}{}
	}
	strs := make([]string, 0, len(callCtxs))
	for c := range callCtxs {
		strs = append(strs, c)
	}

	raw := rawFuncReport{
		Name: r.Name,
		Unsoundness: rawUnsoundness{
			Features: rawUnsoundFeatures{
				Recovers:           stringifyPosMap(r.Unsoundness.Features.Recovers),
				UnsafeUsages:       stringifyPosMap(r.Unsoundness.Features.UnsafeUsages),
				ReflectUsages:      stringifyPosMap(r.Unsoundness.Features.ReflectUsages),
				HasUnboundedDefers: r.Unsoundness.Features.HasUnboundedDefers,
			},
			TimedOut: r.Unsoundness.TimedOut,
		},
		IntraTimeMs:  r.IntraTime.Microseconds(),
		CallContexts: strs,
	}
	b := &bytes.Buffer{}
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(raw); err != nil {
		return b.Bytes(), err
	}

	return b.Bytes(), nil
}

func stringifyPosMap[V any](m map[token.Position]V) map[string]V {
	res := make(map[string]V)
	for k, v := range m {
		res[k.String()] = v
	}
	return res
}

type incompleteFuncReport struct {
	summary     *dataflow.SummaryGraph
	Func        *ssa.Function
	Unsoundness UnsoundnessReport
	IntraTime   time.Duration
}

type UnsoundnessReport struct {
	Features dataflow.UnsoundFeaturesMap
	TimedOut bool
}
