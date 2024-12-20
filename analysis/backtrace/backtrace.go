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

// Package backtrace defines a dataflow analysis that finds all the backwards
// dataflow paths from an entrypoint. This analysis finds data flows which means
// that a backtrace consists of the data flowing backwards from an argument to
// the "backtracepoint" (entrypoint) call.
package backtrace

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// An AnalysisResult from the backtrace analysis contains a constructed a Graph representing the inter-procedural graph
// along with the traces found by the backtrace analysis in Traces
type AnalysisResult struct {
	// Graph is the cross function dataflow graph built by the dataflow analysis. It contains the linked summaries of
	// each function appearing in the program and analyzed.
	Graph df.InterProceduralFlowGraph

	// Traces represents all the paths where data flows out from the analysis entry points for each problem tag.
	Traces map[string]map[df.GraphNode][]Trace
}

// AnalysisReqs provides constraints on the backtrace analysis to run.
type AnalysisReqs struct {
	// Tag is the tag to analyze, ignored if non-empty.
	Tag string
}

// ErrMaxDepth is the error when the max depth is exceeded.
var ErrMaxDepth = errors.New("configured max depth exceeded")

// Analyze runs the analysis on the program prog with the user-provided configuration config.
// If the analysis run successfully, an AnalysisResult is returned, containing all the information collected.
//
// - cfg is the configuration that determines which functions are sources, sinks and sanitizers.
//
// - prog is the built ssa representation of the program. The program must contain a main package and include all its
// dependencies, otherwise the pointer analysis will fail.
func Analyze(state *df.State, reqs AnalysisReqs) (AnalysisResult, error) {
	// Number of working routines to use in parallel. TODO: make this an option?
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	df.RunIntraProceduralPass(state, numRoutines, df.IntraAnalysisParams{
		ShouldBuildSummary: df.ShouldBuildSummary,
		ShouldTrack:        df.IsNodeOfInterest,
	})

	var errs []error
	allTraces := make(map[string]map[df.GraphNode][]Trace)
	for _, ps := range state.Config.SlicingProblems {
		// Check the tag must be analyzed
		if reqs.Tag != "" && ps.Tag != reqs.Tag {
			state.Logger.Infof("Ignoring problem tagged %s since tag to analyze is provided.", ps.Tag)
			continue
		}
		// Check the problem applies to the current target
		if !config.TargetIncludes(ps.Targets, state.Target) {
			continue
		}
		// Number of alarms is problem specific, not global
		state.ResetAlarms()

		state.Logger.Infof("Analyzing slicing problem %s", ps.Tag)
		if ps.MustBeStatic {
			state.Logger.Infof("Will check that data flowing to backtrace points is static.\n")
		}
		// Set problem-specific options
		prevOptions := state.Config.AnalysisProblemOptions

		// Overriding options with problem-specific config
		if ps.AnalysisProblemOptions != nil {
			config.OverrideWithAnalysisOptions(state.Logger, state.Config, ps.AnalysisProblemOptions)
		} else {
			ps.AnalysisProblemOptions = &config.AnalysisProblemOptions{}
		}

		visitor := &Visitor{
			SlicingSpec: &ps,
			Traces:      make(map[df.GraphNode][]Trace),
		}
		df.RunInterProcedural(state, visitor, df.ScanningSpec{
			IsEntryPointSsa: func(node ssa.Node) bool {
				return df.IsBacktraceNode(state, visitor.SlicingSpec, node)
			},
		})
		// filter unwanted nodes
		resTraces := filterResultTraces(state, visitor)
		if len(resTraces) > 0 {
			allTraces[ps.Tag] = resTraces
			state.Report.AddEntry(
				state,
				config.ReportDesc{
					Tool:     config.BacktraceTool,
					Tag:      ps.Tag,
					Severity: ps.Severity,
					Content:  report(state, resTraces, &ps),
				},
			)

			if visitor.SlicingSpec.MustBeStatic {
				state.Logger.Errorf("Found flows of non-static data to backtrace points!")
			}
		}

		if len(visitor.Errs) > 0 {
			vErrs := make([]error, 0, len(visitor.Errs))
			for _, err := range visitor.Errs {
				vErr := fmt.Errorf("%v %v\n", formatutil.Red("error"), err)
				vErrs = append(vErrs, vErr)
			}
			errs = append(errs, vErrs...)
		}
		// Restore global options
		state.Config.AnalysisProblemOptions = prevOptions
	}

	return AnalysisResult{Graph: *state.FlowGraph, Traces: allTraces}, errors.Join(errs...)
}

func filterResultTraces(state *df.State, visitor *Visitor) map[df.GraphNode][]Trace {
	resTraces := make(map[df.GraphNode][]Trace)
	for entry, traces := range visitor.Traces {
		for _, trace := range traces {
			vTrace := Trace{}
			for _, node := range trace {
				if isFiltered(visitor.SlicingSpec, node.GraphNode) {
					state.Logger.Tracef("FILTERED: %v\n", node)
					state.Logger.Tracef("\t%v\n", vTrace)
					vTrace = nil
					break
				}
				vTrace = append(vTrace, node)
			}
			if len(vTrace) > 0 {
				resTraces[entry] = append(resTraces[entry], vTrace)
			}
		}
	}
	return resTraces
}

// Visitor implements the dataflow.Visitor interface and holds the specification of the problem to solve in the
// SlicingSpec as well as the set of traces.
type Visitor struct {
	SlicingSpec   *config.SlicingSpec
	Traces        map[df.GraphNode][]Trace
	Errs          []error
	prevEdgeInfos map[*df.CallNodeArg][]df.EdgeInfo
}

// Visit runs an inter-procedural backwards analysis to add any detected backtraces to v.Traces.
func (v *Visitor) Visit(s *df.State, entrypoint df.NodeWithTrace) {
	if v.prevEdgeInfos == nil {
		v.prevEdgeInfos = make(map[*df.CallNodeArg][]df.EdgeInfo)
	}

	// this is needed because for some reason isBacktracePoint returns true for
	// some synthetic nodes
	call, ok := entrypoint.Node.(*df.CallNode)
	if !ok {
		return
	}

	// the analysis operates on data originating from every argument in every
	// call to an entrypoint
	for _, arg := range call.Args() {
		if err := v.visit(s, arg); err != nil {
			v.Errs = append(v.Errs, err)
		}

		// report traces from entrypoint:
		logger := s.Logger
		traces := v.Traces[arg]
		for i, trace := range traces {
			logger.Infof("%v\n", trace.String())

			// Stop if there is a limit on number of alarms (representing number of traces to report), and it has been reached.
			if s.Config.MaxAlarms > 0 && i >= s.Config.MaxAlarms {
				break
			}

			if err := validateTrace(trace); err != nil {
				panic(fmt.Errorf("invalid trace: %v", err))
			}
		}
	}
}

//gocyclo:ignore
func (v *Visitor) visit(s *df.State, entrypoint *df.CallNodeArg) error {
	logger := s.Logger

	pos := entrypoint.Position(s)
	if !pos.IsValid() {
		pos = entrypoint.ParentNode().Position(s)
	}

	// Skip entrypoint if it is in a dependency or in the Go standard library/runtime
	// TODO make this an option in the config
	if strings.Contains(pos.Filename, "vendor") || strings.Contains(pos.Filename, runtime.GOROOT()) {
		logger.Debugf("%s %v\n", formatutil.Red("Skipping entrypoint"), entrypoint.String())
		return nil
	}

	logger.Infof("\n%s ENTRYPOINT %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Infof("==> Node: %s\n", formatutil.Purple(entrypoint.String()))
	logger.Infof("%s %s\n", formatutil.Green("Found at"), pos)

	entry := df.NodeWithTrace{Node: entrypoint, Trace: &df.NodeTree[*df.CallNode]{}}
	seen := make(map[df.KeyType]bool)
	goroutines := make(map[*ssa.Go]bool)
	root := &df.VisitorNode{
		NodeWithTrace: entry,
		AccessPaths:   []string{""},
		Prev:          nil,
		Depth:         0,
		Status:        df.VisitorNodeStatus{Kind: df.DefaultTracing},
	}
	stack := []*df.VisitorNode{root}

	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		// Check that the node does not correspond to a non-constructed summary
		if !cur.Node.Graph().Constructed {
			if !s.Config.SummarizeOnDemand {
				logger.Tracef("%s: summary has not been built for %s.",
					formatutil.Yellow("WARNING"),
					formatutil.Yellow(cur.Node.Graph().Parent.Name()))

				// In that case, continue as there is no information on data flow
				continue
			}

			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			v.onDemandIntraProcedural(s, cur.Node.Graph())
		}

		// Base case: add the trace if there are no more (intra- or inter-procedural) incoming edges from the node
		if isBaseCase(cur.Node, s.Config) {
			t := findTrace(s, cur)
			addTrace(v, entrypoint, t)

			logger.Tracef("Base case reached...")
			logger.Tracef("Adding trace: %v\n", t)
			continue
		}

		if s.Config.ExceedsMaxDepth(cur.Depth) {
			t := findTrace(s, cur)
			addTrace(v, entrypoint, t)
			err := fmt.Errorf("call trace %w: %d", ErrMaxDepth, cur.Depth)
			s.Report.AddError("max-depth", err)
			logger.Errorf("%v\n", err)
			continue
		}

		traceNode(s, cur)

		switch graphNode := cur.Node.(type) {
		// Data flows from the function parameter to the corresponding function call argument at the call site.
		case *df.ParamNode:
			if cur.Prev.Node.Graph() != graphNode.Graph() {
				// Flows inside the function body. The data propagates to other locations inside the function body
				for nextNode := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			}

			// when the previous is a bound label or var, we have lost context
			// this can be remediated once we implement the same closure-tracking mechanism as in the taint analysis.
			_, isFromBoundLabel := cur.Prev.Node.(*df.BoundLabelNode)
			_, isFromBoundVar := cur.Prev.Node.(*df.BoundVarNode)
			// If the parameter was visited from an inter-procedural edge (i.e. from a call argument node), then data
			// must flow back to that argument.
			var callSite *df.CallNode
			if cur.Trace.Len() > 0 {
				callSite = df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace)
			}
			if callSite != nil && !isFromBoundLabel && !isFromBoundVar {
				if err := df.CheckIndex(s, graphNode, callSite, "[Context] No argument at call site"); err != nil {
					s.Report.AddError("argument at call site "+graphNode.String(), err)
					// TODO fix bug that leads to panic
					// report trace in the error as well
					t := findTrace(s, cur)
					return fmt.Errorf("[Context] no arg at call site %v when visiting node %v: %v\n\t%v", callSite, graphNode, err, t)
					// panic(fmt.Errorf("[Context] no arg at call site %v when visiting node %v: %v", callSite, graphNode, err))
				}

				nextNodeArg := callSite.Args()[graphNode.Index()]
				if nextNodeArg != nil {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNodeArg,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			} else {
				callSites := graphNode.Graph().Callsites
				// No context: the value must always flow back to all call sites
				for _, callSite := range callSites {
					if err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
						s.Report.AddError("argument at call site "+graphNode.String(), err)
						panic(fmt.Errorf("[No Context] no arg at call site %v when visiting node %v: %v", callSite, graphNode, err))
					}
					callSiteArg := callSite.Args()[graphNode.Index()]
					if !callSiteArg.Graph().Constructed {
						v.onDemandIntraProcedural(s, callSiteArg.Graph())
					}
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         callSiteArg,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			}

		// Data flows backwards within the function from the function call argument.
		case *df.CallNodeArg:
			prevStackLen := len(stack)

			callSite := graphNode.ParentNode()
			if lang.IsNillableType(graphNode.Type()) {
				logger.Tracef("arg is nillable\n")
				if callSite.CalleeSummary == nil || !callSite.CalleeSummary.Constructed { // this function has not been summarized
					if s.Config.SummarizeOnDemand {
						if callSite.Callee() == nil {
							panic(fmt.Errorf("callsite %v has no callee", callSite))
						}

						// the callee summary may not have been created yet
						if callSite.CalleeSummary == nil {
							logger.Tracef("Callee summary has not been created")
							callSite.CalleeSummary = df.NewSummaryGraph(s,
								callSite.Callee(),
								df.GetUniqueFunctionID(),
								func(s *df.State, n ssa.Node) bool { return df.IsBacktraceNode(s, nil, n) },
								nil)
							v.onDemandIntraProcedural(s, callSite.CalleeSummary)
						}
					} else {
						s.ReportMissingOrNotConstructedSummary(callSite)
						break
					}
				}

				// Computing context-sensitive information for the analyses

				// Obtain the parameter node of the callee corresponding to the argument in the call site
				// Data flows backwards from the argument to the corresponding parameter
				// if the parameter is a nillable type (can be modified)
				param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
				if param != nil {
					// This is where a function gets "called" and the next nodes will be analyzed in a different context
					nextNode := callSite.CalleeSummary.Params[param]
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace.Add(callSite),
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				} else {
					s.Report.AddError(
						fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
						fmt.Errorf("position %d", graphNode.Index()))
					panic("nil param")
				}
			}

			// If the arg value is bound, make sure to visit all of its outgoing values
			// because they are all part of the dataflow in the trace
			//
			// See Examples 5 and 16 in ./testdata/closures/main.go
			if _, ok := s.BoundingInfo[graphNode.Value()]; ok {
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						var added bool
						stack, added = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
						if added {
							v.prevEdgeInfos[graphNode] = append(v.prevEdgeInfos[graphNode], edgeInfo)
						}
					}
				}
			}

			// We pop the call from the trace (callstack) when exiting the callee and returning to the caller
			var tr *df.NodeTree[*df.CallNode]
			if cur.Trace.Len() > 0 {
				tr = cur.Trace.Parent
			}

			// Check if the previous node was a parameter coming from the same function (recursive call)
			prevIsRecursiveParam := false
			if cur.Prev != nil {
				if param, ok := cur.Prev.Node.(*df.ParamNode); ok {
					prevIsRecursiveParam = param.Graph() == callSite.Graph()
				}
			}
			// Data flows backwards from the argument within the function
			if cur.Prev == nil || callSite.Graph() != cur.Prev.Node.Graph() || prevIsRecursiveParam {
				for nextNode, edgeInfo := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        tr,
						ClosureTrace: cur.ClosureTrace,
					}
					var added bool
					stack, added = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					if added {
						v.prevEdgeInfos[graphNode] = append(v.prevEdgeInfos[graphNode], edgeInfo)
					}
				}
			}

			// Arg base case:
			// - matching parameter was not detected, or
			// - value is not bound, and
			// - no more incoming edges from the arg
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				addTrace(v, entrypoint, t)
				logger.Tracef("CallNodeArg base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the return statement.
		case *df.ReturnValNode:
			for nextNode := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

		// Data flows from the function call to the called function's return statement.
		// It also flows backwards within the parent function.
		case *df.CallNode:
			df.CheckNoGoRoutine(s, goroutines, graphNode)

			prevStackLen := len(stack)

			if graphNode.Callee() == nil {
				panic(fmt.Errorf("node %v callee is nil", graphNode))
			}

			// HACK: Make the callsite's callee summary point to the actual function summary, not the "bound" summary
			// This is needed because "bound" summaries can be incomplete
			// TODO Is there a better way to identify a "bound" function?
			if graphNode.CalleeSummary == nil ||
				!graphNode.CalleeSummary.Constructed ||
				strings.Contains(graphNode.ParentName(), "$bound") {

				v.onDemandIntraProcedural(s, graphNode.CalleeSummary)
			}

			if len(graphNode.CalleeSummary.Returns) == 0 {
				panic(fmt.Errorf("node %v callee %v summary has no returns: %v", graphNode, graphNode.CalleeSummary.Parent, graphNode.CalleeSummary))
			}
			for _, rets := range graphNode.CalleeSummary.Returns {
				for _, ret := range rets {
					// We add the caller's node to the trace (callstack) when flowing to the callee's return node
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         ret,
						Trace:        cur.Trace.Add(graphNode),
						ClosureTrace: cur.ClosureTrace,
					}

					var prevEdges []df.EdgeInfo
					if cur.Prev != nil && cur.Prev.Node != nil {
						if arg, ok := cur.Prev.Node.(*df.CallNodeArg); ok {
							if infos, ok := v.prevEdgeInfos[arg]; ok {
								prevEdges = infos
							}
						}
					}
					if len(prevEdges) > 0 {
						// Use edgeInfos from call node arg: this is needed to visit the correct
						// return node index if it is a tuple
						for _, edgeInfo := range prevEdges {
							stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
						}
					} else {
						stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					}
				}
			}

			for nextNode := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

			// Call node base case:
			// - no new (non-visited) matching return, and
			// - no more incoming edges from the call
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				addTrace(v, entrypoint, t)
				logger.Tracef("CallNode base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the synthetic node or builtin call node.
		case *df.SyntheticNode, *df.BuiltinCallNode:
			for nextNode := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

		// From a global write node, data flows backwards intra-procedurally.
		// From a read location, backwards data flow follows ALL the write locations of the node.
		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				for nextNode := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			} else {
				if s.Config.SummarizeOnDemand {
					logger.Tracef("Global %v SSA instruction: %v\n", graphNode, graphNode.Instr())
					for f := range s.ReachableFunctions() {
						if lang.FnWritesTo(f, graphNode.Global.Value()) {
							logger.Tracef("Global %v written in function: %v\n", graphNode, f)
							df.BuildSummary(s, f)
						}
					}
				}

				for nextNode := range graphNode.Global.WriteLocations {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        nil,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			}

		case *df.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the dataflow edges between arguments
			for nextNode := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

			closureNode := graphNode.ParentNode()
			if !closureNode.ClosureSummary.Constructed {
				v.onDemandIntraProcedural(s, closureNode.ClosureSummary)
				s.FlowGraph.Sync()
			}

			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv == nil {
				panic(fmt.Errorf("no free variable matching bound variable in %s at position %d",
					closureNode.ClosureSummary.Parent.String(), graphNode.Index()))
			}
			nextNode := closureNode.ClosureSummary.FreeVars[fv]
			nextNodeWithTrace := df.NodeWithTrace{
				Node:         nextNode,
				Trace:        df.UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}
			stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)

		case *df.FreeVarNode:
			prevStackLen := len(stack)

			// Flows inside the function
			if cur.Prev.Node.Graph() != graphNode.Graph() {
				for nextNode := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			} else if cur.ClosureTrace != nil {
				// Flow to the matching bound variables at the make closure site from the closure trace
				bvs := cur.ClosureTrace.Label.BoundVars()
				if len(bvs) == 0 {
					panic("no bound vars")
				}
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         bv,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace.Parent,
					}
					status := df.VisitorNodeStatus{
						Kind:        df.ClosureTracing,
						TracingInfo: cur.Status.TracingInfo.Next(cur.ClosureTrace.Label.ClosureSummary, graphNode.Index()),
					}
					stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, status, df.EdgeInfo{}, seen)
				} else {
					panic(fmt.Errorf("no bound variable matching free variable in %s at position %d: %v. bound variables: %v. call trace: %v. closure trace: %v",
						cur.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index(), graphNode, bvs, cur.Trace, cur.ClosureTrace))
				}
			} else {
				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					// Summarize the free variable's closure's parent function if there is one
					f := graphNode.Graph().Parent.Parent()
					if f == nil {
						panic(fmt.Errorf("closure's parent function does not exist for free variable: %v", graphNode))
					}
					summary := df.BuildSummary(s, f)
					v.onDemandIntraProcedural(s, summary)
					// This is needed to get the referring make closures outside the function
					s.FlowGraph.BuildGraph()
				}

				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
				}

				// If there is no closure trace, there is no calling context so
				// flow to every make closure site in the graph
				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         bv,
							Trace:        cur.Trace,
							ClosureTrace: nil,
						}
						stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					} else {
						panic(fmt.Errorf("[No Context] no bound variable matching free variable in %s at position %d",
							makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
					}
				}
			}

			// Free var base case:
			// - no new matching bound variables
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				addTrace(v, entrypoint, t)
				logger.Tracef("Free var base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		case *df.ClosureNode:
			// Data flows backwards from the bound variables of the closure.
			// A bound variable is a variable inside a closure definition (callee).
			for _, bv := range graphNode.BoundVars() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         bv,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

		case *df.BoundLabelNode:
			if v.SlicingSpec.SkipBoundLabels {
				break
			}
			for nextNode := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack, _ = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

		default:
			panic(fmt.Errorf("unhandled graph node type: %T", graphNode))
		}
	}

	return nil
}

// onDemandIntraProcedural runs the intra-procedural on the summary, modifying its state
// This panics when the analysis fails, because it is expected that an error will cause any further result
// to be invalid.
func (v *Visitor) onDemandIntraProcedural(s *df.State, summary *df.SummaryGraph) {
	s.Logger.Debugf("[On-demand] Summarizing %s...", summary.Parent)
	elapsed, err := df.RunIntraProcedural(s, summary)
	s.Logger.Debugf("%-12s %-90s [%.2f s]\n", " ", summary.Parent.String(), elapsed.Seconds())
	if err != nil {
		panic(fmt.Sprintf("failed to run intra-procedural analysis : %v", err))
	}
}

// addNext adds the node to stack, setting cur as the previous node and checking that node with the
// trace has not been seen before.
// Returns the new stack and a boolean indicating if the next node was added.
//
// - stack is the DFS stack in the calling algorithm
//
// - cur is the current visitor node
//
// - nextNodeWithTrace is the graph node to add to the stack, with the new call stack trace and closure stack trace
//
// - edgeInfo is the label of the edge from cur's node to add
//
// - seen is the set of nodes that have been visited
func (v *Visitor) addNext(s *df.State,
	stack []*df.VisitorNode,
	cur *df.VisitorNode,
	nextNodeWithTrace df.NodeWithTrace,
	nextStatus df.VisitorNodeStatus,
	edgeInfo df.EdgeInfo,
	seen map[df.KeyType]bool) ([]*df.VisitorNode, bool) {

	// Adding the next node with trace in a visitor node to the queue, and recording the "execution" tree
	nextVisitorNode := &df.VisitorNode{
		NodeWithTrace: nextNodeWithTrace,
		AccessPaths:   nil,
		Status:        nextStatus,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}

	// Tuple sensitivity: check edge info
	if ret, ok := nextNodeWithTrace.Node.(*df.ReturnValNode); ok {
		if arg, ok := cur.Prev.Node.(*df.CallNodeArg); ok {
			_, hasEdgeInfo := v.prevEdgeInfos[arg]
			if hasEdgeInfo && ret.Index() != edgeInfo.Index {
				s.Logger.Tracef("Return node index %d != edgeInfo index %d\n", ret.Index(), edgeInfo.Index)
				return stack, false
			}
		}
	}

	// First stop condition: node has already been seen
	key := nextVisitorNode.Key()
	if seen[key] {
		s.Logger.Tracef("Will not add %v\n", nextNodeWithTrace.Node.String())
		s.Logger.Tracef("\tseen? %v, depth %v\n", seen[key], cur.Depth)
		return stack, false
	}

	// Second set of stop conditions: trace or closure trace is a lasso
	if nextNodeWithTrace.Trace.GetLassoHandle() != nil || nextNodeWithTrace.ClosureTrace.GetLassoHandle() != nil {
		s.Logger.Tracef("Will not add %v\n", cur.Node.String())
		s.Logger.Tracef("\tcall trace: %v\n", nextVisitorNode.Trace)
		s.Logger.Tracef("\tcall lasso? %v\n", nextVisitorNode.Trace.GetLassoHandle() != nil)
		s.Logger.Tracef("\tclosure-trace: %v\n", nextVisitorNode.ClosureTrace)
		s.Logger.Tracef("\tclosure lasso? %v\n", nextVisitorNode.ClosureTrace.GetLassoHandle() != nil)
		return stack, false
	}

	s.Logger.Tracef("Adding %v at %v\n", nextVisitorNode.Node, nextVisitorNode.Node.Position(s))

	cur.AddChild(nextVisitorNode)
	stack = append(stack, nextVisitorNode)
	seen[key] = true
	return stack, true
}

// isBaseCase returns true if the analysis should not analyze node any further.
func isBaseCase(node df.GraphNode, cfg *config.Config) bool {
	hasIntraIncomingEdges := len(node.In()) != 0
	canHaveInterIncomingEdges := func(node df.GraphNode) bool {
		if global, ok := node.(*df.AccessGlobalNode); ok {
			if cfg.SummarizeOnDemand && !global.IsWrite {
				// with on-demand summarization, global.Global.WriteLocations may not be fully populated
				// so assume that there are always inter-procedural edges from a global read node
				return true
			}
			return (global.IsWrite && len(global.In()) > 0) || (!global.IsWrite && len(global.Global.WriteLocations) > 0)
		}
		_, isParam := node.(*df.ParamNode)     // param should not have intra-procedural incoming edges
		_, isCall := node.(*df.CallNode)       // call may have inter-procedural edges
		_, isCallArg := node.(*df.CallNodeArg) // call argument may have inter-procedural edges
		hasIntraIncomingEdges = hasIntraIncomingEdges && !isCallArg
		_, isClosure := node.(*df.ClosureNode)   // closure data flows backwards to its bound variables
		_, isBoundVar := node.(*df.BoundVarNode) // bound variables may flow to free variables
		_, isFreeVar := node.(*df.FreeVarNode)   // free variables may flow to closure nodes
		return isParam || isCall || isCallArg || isClosure || isBoundVar || isFreeVar
	}(node)

	return !hasIntraIncomingEdges && !canHaveInterIncomingEdges
}

// findTrace returns a slice of all the nodes in the trace starting from end.
func findTrace(s *df.State, end *df.VisitorNode) Trace {
	trace := Trace{}
	cur := end
	for cur != nil {
		node := TraceNode{
			GraphNode: cur.Node,
			Pos:       cur.Node.Position(s),
		}
		trace = append(trace, node)
		cur = cur.Prev
	}

	return trace
}

func addTrace(v *Visitor, entrypoint *df.CallNodeArg, trace Trace) {
	end := trace[0]
	// Don't add traces when the tool is looking for flows that violate must-be-static constraint
	if v.SlicingSpec.MustBeStatic && IsStatic(end.GraphNode) {
		return
	}
	// don't add trace if it's already in v.Traces
	for _, t := range v.Traces[entrypoint] {
		// need this more complex logic because you can't compare slices directly
		if len(t) == len(trace) {
			same := true
			for i, tn := range t {
				if tn != trace[i] {
					same = false
					break
				}
			}
			if same {
				return
			}
		}
	}

	v.Traces[entrypoint] = append(v.Traces[entrypoint], trace)
}

// IsStatic returns true if node is a constant value.
// TODO make this better
func IsStatic(node df.GraphNode) bool {
	switch node := node.(type) {
	case *df.CallNodeArg:
		return lang.IsStaticallyDefinedLocal(node.Value())
	default:
		return false
	}
}

// traceNode prints trace information about node.
func traceNode(s *df.State, node *df.VisitorNode) {
	logger := s.Logger
	if !logger.LogsTrace() {
		return
	}
	logger.Tracef("----------------\n")
	logger.Tracef("Visiting %T node: %v\n\tat %v\n", node.Node, node.Node, node.Node.Position(s))
	logger.Tracef("Element status: %v\n", node.Status)
	logger.Tracef("Element trace: %s\n", node.Trace.String())
	logger.Tracef("Element closure trace: %s\n", node.ClosureTrace.String())
	logger.Tracef("Element backtrace: %v\n", findTrace(s, node))
}

func isFiltered(ss *config.SlicingSpec, n df.GraphNode) bool {
	var f *ssa.Function
	switch node := n.(type) {
	case *df.CallNode:
		f = node.CallSite().Parent()
	case *df.CallNodeArg:
		f = node.ParentNode().CallSite().Parent()
	}
	typ := n.Type()

	for _, filter := range ss.Filters {
		if filter.Type != "" {
			if filter.MatchType(typ) {
				return true
			}
		}
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}
	return false
}

// validateTrace validates trace.
// TODO implement more checks
func validateTrace(trace Trace) error {
	for i, cur := range trace {
		j := i + 1
		if j == len(trace) {
			continue
		}
		next := trace[j]

		switch cur := cur.GraphNode.(type) {
		case *df.CallNodeArg:
			if arg, ok := next.GraphNode.(*df.CallNodeArg); ok && arg.ParentName() != cur.ParentName() {
				return fmt.Errorf("two interprocedural call args in a row: %v -> %v", cur, next.GraphNode)
			}
		case *df.ParamNode:
			if param, ok := next.GraphNode.(*df.ParamNode); ok && param.ParentName() != cur.ParentName() {
				return fmt.Errorf("two interprocedural params in a row: %v -> %v", cur, next.GraphNode)
			}
		}
	}

	return nil
}
