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
	"fmt"
	"go/token"
	"runtime"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// An AnalysisResult from the backtrace analysis contains a constructed a Graph representing the inter-procedural graph
// along with the traces found by the backtrace analysis in Traces
type AnalysisResult struct {
	// Graph is the cross function dataflow graph built by the dataflow analysis. It contains the linked summaries of
	// each function appearing in the program and analyzed.
	Graph df.InterProceduralFlowGraph

	// Traces represents all the paths where data flows out from the analysis entry points.
	Traces []Trace
}

// Trace represents a dataflow path (sequence of nodes) out of an analysis
// entrypoint.
//
// The first node in the trace is the origin of the data flow.
//
// The last node in the trace is an argument to the backtrace entrypoint function
// defined in the config.
type Trace []TraceNode

func (t Trace) String() string {
	return "\n" + strings.Join(funcutil.Map(t, func(n TraceNode) string { return "\t" + n.String() }), "\n")
}

func (t Trace) Key() df.KeyType {
	keys := make([]string, 0, len(t))
	for _, node := range t {
		keys = append(keys, node.Node.LongID())
	}

	return strings.Join(keys, "_")
}

// TraceNode represents a node in the trace.
type TraceNode struct {
	*df.VisitorNode
	Pos    token.Position
	Values []string // TODO maybe
}

func (n TraceNode) String() string {
	if n.VisitorNode == nil {
		return ""
	}
	if n.VisitorNode.Node == nil {
		return ""
	}

	return fmt.Sprintf("%v at %v", n.VisitorNode.Node.String(), n.Pos)
}

// Analyze runs the analysis on the program prog with the user-provided configuration config.
// If the analysis run successfully, an AnalysisResult is returned, containing all the information collected.
//
// - cfg is the configuration that determines which functions are sources, sinks and sanitizers.
//
// - prog is the built ssa representation of the program. The program must contain a main package and include all its
// dependencies, otherwise the pointer analysis will fail.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram) (AnalysisResult, error) {
	// Number of working routines to use in parallel. TODO: make this an option?
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	prog := lp.Program
	logger := config.NewLogGroup(cfg)
	state, err := df.NewInitializedAnalyzerState(logger, cfg, prog)
	if err != nil {
		return AnalysisResult{}, err
	}

	if cfg.SummarizeOnDemand {
		logger.Infof("On-demand summarization is enabled")
		intraProceduralPassWithOnDemand(state, numRoutines)
	} else {
		// Only build summaries for non-stdlib functions here
		analysis.RunIntraProceduralPass(state, numRoutines, analysis.IntraAnalysisParams{
			ShouldBuildSummary: df.ShouldBuildSummary,
			IsEntrypoint:       isSomeIntraProceduralEntryPoint,
		})
	}

	traces := []Trace{}
	for _, ps := range cfg.SlicingProblems {
		visitor := &Visitor{
			SlicingSpec: &ps,
		}
		analysis.RunInterProcedural(state, visitor, analysis.InterProceduralParams{
			IsEntrypoint: func(node ssa.Node) bool {
				return IsInterProceduralEntryPoint(state, visitor.SlicingSpec, node)
			},
		})
		// filter unwanted nodes
		vTraces := []Trace{}
		for _, trace := range visitor.Traces {
			vTrace := Trace{}
			for _, node := range trace {
				if isFiltered(visitor.SlicingSpec, node.Node) {
					logger.Tracef("FILTERED: %v\n", node)
					logger.Tracef("\t%v\n", vTrace)
					vTrace = nil
					break
				}
				vTrace = append(vTrace, node)
			}
			if len(vTrace) > 0 {
				vTraces = append(vTraces, vTrace)
			}
		}
		traces = append(traces, vTraces...)
	}

	logger.Infof(formatutil.Green("Found %d traces.\n"), len(traces))

	return AnalysisResult{Graph: *state.FlowGraph, Traces: traces}, nil
}

// Visitor implements the dataflow.Visitor interface and holds the specification of the problem to solve in the
// SlicingSpec as well as the set of traces.
type Visitor struct {
	SlicingSpec *config.SlicingSpec
	Traces      []Trace
}

// Visit runs an inter-procedural backwards analysis to add any detected backtraces to v.Traces.
func (v *Visitor) Visit(s *df.AnalyzerState, entrypoint df.NodeWithTrace) {
	// this is needed because for some reason isBacktracePoint returns true for
	// some synthetic nodes
	call, ok := entrypoint.Node.(*df.CallNode)
	if !ok {
		return
	}

	// the analysis operates on data originating from every argument in every
	// call to an entrypoint
	for _, arg := range call.Args() {
		v.visit(s, arg)
	}
}

//gocyclo:ignore
func (v *Visitor) visit(s *df.AnalyzerState, entrypoint *df.CallNodeArg) {
	pos := entrypoint.Position(s)
	if !pos.IsValid() {
		pos = entrypoint.ParentNode().Position(s)
	}

	logger := s.Logger
	logger.Infof("\n%s ENTRYPOINT %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Infof("==> Node: %s\n", formatutil.Purple(entrypoint.String()))
	logger.Infof("%s %s\n", formatutil.Green("Found at"), pos)

	// Skip entrypoint if it is in a dependency or in the Go standard library/runtime
	// TODO make this an option in the config
	if strings.Contains(pos.Filename, "vendor") || strings.Contains(pos.Filename, runtime.GOROOT()) {
		logger.Infof("%s\n", formatutil.Red("Skipping..."))
		return
	}

	var trace *df.NodeTree[*df.CallNode]
	entry := df.NodeWithTrace{Node: entrypoint, Trace: trace}
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

	var cur *df.VisitorNode
	for len(stack) != 0 {
		cur = stack[len(stack)-1]
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
			if _, err := df.RunIntraProcedural(s, cur.Node.Graph()); err != nil {
				panic(fmt.Errorf("failed to run the intra-procedural analysis: %v", err))
			}
		}

		// Base case: add the trace if there are no more (intra- or inter-procedural) incoming edges from the node
		if isBaseCase(cur.Node, s.Config) {
			t := findTrace(s, cur)
			v.Traces = append(v.Traces, t)

			logger.Tracef("Base case reached...")
			logger.Tracef("Adding trace: %v\n", t)
			continue
		}

		traceNode(s, cur)

		switch graphNode := cur.Node.(type) {
		// Data flows from the function parameter to the corresponding function call argument at the call site.
		case *df.ParamNode:
			if cur.Prev.Node.Graph() != graphNode.Graph() {
				// Flows inside the function body. The data propagates to other locations inside the function body
				for nextNode, edgeInfo := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
				}
			}

			// If the parameter was visited from an inter-procedural edge (i.e. from a call argument node), then data
			// must flow back to that argument.
			if cur.Trace.Len() > 0 && cur.Trace.Label != nil {
				callSite := cur.Trace.Label
				if err := df.CheckIndex(s, graphNode, callSite, "[Context] No argument at call site"); err != nil {
					s.AddError("argument at call site "+graphNode.String(), err)
					panic("no arg at call site")
				} else {
					nextNodeArg := callSite.Args()[graphNode.Index()]
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNodeArg,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					continue
				}
			}

			// No context: the value must always flow back to all call sites
			for _, callSite := range callSites {
				if err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
					s.AddError("argument at call site "+graphNode.String(), err)
					panic("[No Context] no arg at call site")
				} else {
					arg := callSite.Args()[graphNode.Index()]
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         arg,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
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
							panic("callsite has no callee")
						}

						// the callee summary may not have been created yet
						if callSite.CalleeSummary == nil {
							callSite.CalleeSummary = df.NewSummaryGraph(s, callSite.Callee(), df.GetUniqueFunctionID(),
								isSomeIntraProceduralEntryPoint, nil)
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
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				} else {
					s.AddError(
						fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
						fmt.Errorf("position %d", graphNode.Index()))
					panic("nil param")
				}
			}

			// If the arg value is bound, make sure to visit all of its outgoing values
			// because they are all part of the dataflow in the trace
			//
			// See Examples 5 and 16 in argot/testdata/src/taint/closures/main.go
			if _, ok := s.BoundingInfo[graphNode.Value()]; ok {
				for nextNode, edgeInfo := range graphNode.Out() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
				}
			}

			// We pop the call from the trace (callstack) when exiting the callee and returning to the caller
			var tr *df.NodeTree[*df.CallNode]
			if cur.Trace != nil {
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
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
				}
			}

			// Arg base case:
			// - matching parameter was not detected, or
			// - value is not bound, and
			// - no more incoming edges from the arg
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				v.Traces = append(v.Traces, t)
				logger.Tracef("CallNodeArg base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the return statement.
		case *df.ReturnValNode:
			for nextNode, edgeInfo := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
			}

		// Data flows from the function call to the called function's return statement.
		// It also flows backwards within the parent function.
		case *df.CallNode:
			df.CheckNoGoRoutine(s, goroutines, graphNode)
			prevStackLen := len(stack)

			if graphNode.Callee() == nil {
				panic("nil callee")
			}

			// HACK: Make the callsite's callee summary point to the actual function summary, not the "bound" summary
			// This is needed because "bound" summaries can be incomplete
			// TODO Is there a better way to identify a "bound" function?
			if s.Config.SummarizeOnDemand &&
				(graphNode.CalleeSummary == nil || !graphNode.CalleeSummary.Constructed ||
					strings.Contains(graphNode.ParentName(), "$bound")) {
				graphNode.CalleeSummary = df.BuildSummary(s, graphNode.Callee())
			}

			if graphNode.CalleeSummary != nil {
				for _, rets := range graphNode.CalleeSummary.Returns {
					for _, ret := range rets {
						// We add the caller's node to the trace (callstack) when flowing to the callee's return node
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         ret,
							Trace:        cur.Trace.Add(graphNode),
							ClosureTrace: cur.ClosureTrace,
						}
						stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					}
				}
			} else {
				panic(fmt.Errorf("node's callee summary is nil: %v", graphNode))
			}

			for nextNode, edgeInfo := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
			}

			// Call node base case:
			// - no new (non-visited) matching return, and
			// - no more incoming edges from the call
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				v.Traces = append(v.Traces, t)
				logger.Tracef("CallNode base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the synthetic node.
		case *df.SyntheticNode:
			for nextNode, edgeInfo := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
			}

		// From a global write node, data flows backwards intra-procedurally.
		// From a read location, backwards data flow follows ALL the write locations of the node.
		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				for nextNode, edgeInfo := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
				}
			} else {
				if s.Config.SummarizeOnDemand {
					logger.Tracef("Global %v SSA instruction: %v\n", graphNode, graphNode.Instr())
					for f := range s.ReachableFunctions(false, false) {
						if lang.FnWritesTo(f, graphNode.Global.Value()) {
							logger.Tracef("Global %v written in function: %v\n", graphNode, f)
							df.BuildSummary(s, f)
						}
					}
					//s.FlowGraph.BuildGraph(IsInterProceduralEntryPoint)
				}

				for nextNode := range graphNode.Global.WriteLocations {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        nil,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				}
			}

		case *df.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for nextNode, edgeInfo := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
			}
			closureNode := graphNode.ParentNode()

			if s.Config.SummarizeOnDemand && closureNode.ClosureSummary == nil {
				closureSummary := df.NewSummaryGraph(s, closureNode.Instr().Fn.(*ssa.Function), df.GetUniqueFunctionID(),
					isSomeIntraProceduralEntryPoint, nil)
				if _, err := df.RunIntraProcedural(s, closureSummary); err != nil {
					panic(fmt.Errorf("failed to run intra-procedural analysis for %v: %v", closureSummary.Parent, err))
				}
				closureNode.ClosureSummary = closureSummary
				//closureNode.ClosureSummary = df.BuildSummary(s, closureNode.Instr().Fn.(*ssa.Function))
				//s.FlowGraph.BuildGraph(IsInterProceduralEntryPoint)
				logger.Tracef("closure summary parent: %v\n", closureNode.ClosureSummary.Parent)
			}

			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				nextNode := closureNode.ClosureSummary.FreeVars[fv]
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace.Add(closureNode),
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			} else {
				panic(fmt.Errorf("no free variable matching bound variable in %s at position %d",
					closureNode.ClosureSummary.Parent.String(), graphNode.Index()))
			}

		case *df.FreeVarNode:
			prevStackLen := len(stack)

			// Flows inside the function
			if cur.Prev.Node.Graph() != graphNode.Graph() {
				for nextNode, edgeInfo := range graphNode.In() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
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
					stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
				} else {
					panic(fmt.Errorf("no bound variable matching free variable in %s at position %d",
						cur.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index()))
				}
			} else {
				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					// Summarize the free variable's closure's parent function if there is one
					f := graphNode.Graph().Parent.Parent()
					if f != nil {
						df.BuildSummary(s, f)
					}
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
						stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
					} else {
						panic(fmt.Errorf("[No Context] no bound variable matching free variable in %s at position %d",
							makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
						//s.AddError(
						//	fmt.Sprintf("[No Context] no bound variable matching free variable in %s",
						//		makeClosureSite.ClosureSummary.Parent.String()),
						//	fmt.Errorf("at position %d", graphNode.Index()))
					}
				}
			}

			// Free var base case:
			// - no new matching bound variables
			if prevStackLen == len(stack) {
				t := findTrace(s, cur)
				v.Traces = append(v.Traces, t)
				logger.Tracef("Free var base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		case *df.ClosureNode:
			// Data flows backwards from the bound variables of the closure
			for _, bv := range graphNode.BoundVars() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         bv,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, df.EdgeInfo{}, seen)
			}

		case *df.BoundLabelNode:
			for nextNode, edgeInfo := range graphNode.In() {
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        cur.Trace,
					ClosureTrace: cur.ClosureTrace,
				}
				stack = v.addNext(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo, seen)
			}

		default:
			panic(fmt.Errorf("unhandled graph node type: %T", graphNode))
		}
	}
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
//
// - stack is the DFS stack in the calling algorithm
//
// - cur is the current visitor node
//
// - nextNodeWithTrace is the graph node to add to the queue, with the new call stack trace and closure stack trace
//
// - nextMode is the mode for the next node that will be added
//
// - edgeInfo is the label of the edge from cur's node to toAdd
//
// - seen is the nodes that have been visited
//
//gocyclo:ignore
func (v *Visitor) addNext(s *df.AnalyzerState,
	stack []*df.VisitorNode,
	cur *df.VisitorNode,
	nextNodeWithTrace df.NodeWithTrace,
	nextStatus df.VisitorNodeStatus,
	edgeInfo df.EdgeInfo,
	seen map[df.KeyType]bool) []*df.VisitorNode {

	if len(cur.AccessPaths) == 0 {
		panic("access paths should always at least be the empty string")
	}

	nextNodeAccessPaths := []string{}
	for inPath, outPaths := range edgeInfo.RelPath {
		for outPath := range outPaths {
			// Logic for matching paths
			for _, ap := range cur.AccessPaths {
				if strings.HasPrefix(inPath, ap) {
					nextNodeAccessPaths = append(nextNodeAccessPaths, outPath)
				}
			}
		}
	}
	if len(edgeInfo.RelPath) == 0 || (len(edgeInfo.RelPath) == 1 && edgeInfo.RelPath[""][""]) {
		nextNodeAccessPaths = cur.AccessPaths
	}
	// No matching access paths for this edge
	if len(nextNodeAccessPaths) == 0 {
		return stack
	}

	// Adding the next node with trace in a visitor node to the queue, and recording the "execution" tree
	nextVisitorNode := &df.VisitorNode{
		NodeWithTrace: nextNodeWithTrace,
		AccessPaths:   nextNodeAccessPaths,
		Status:        nextStatus,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}

	// First set of stop conditions: node has already been seen, or depth exceeds limit
	if seen[nextVisitorNode.Key()] || s.Config.ExceedsMaxDepth(cur.Depth) {
		s.Logger.Tracef("Will not add %v\n", nextNodeWithTrace.Node.String())
		s.Logger.Tracef("\tseen? %v, depth %v\n", seen[nextVisitorNode.Key()], cur.Depth)
		return stack
	}

	// Second set of stop conditions: trace or closure trace is a lasso
	if nextVisitorNode.Trace.GetLassoHandle() != nil || nextVisitorNode.ClosureTrace.GetLassoHandle() != nil {
		s.Logger.Tracef("Will not add %v\n", cur.Node.String())
		s.Logger.Tracef("\tcall trace: %v\n", nextVisitorNode.Trace)
		s.Logger.Tracef("\tcall lasso? %v\n", nextVisitorNode.Trace.GetLassoHandle() != nil)
		s.Logger.Tracef("\tclosure-trace: %v\n", nextVisitorNode.ClosureTrace)
		s.Logger.Tracef("\tclosure lasso? %v\n", nextVisitorNode.ClosureTrace.GetLassoHandle() != nil)
		return stack
	}

	s.Logger.Tracef("Adding %v at %v\n", nextVisitorNode.Node, nextVisitorNode.Node.Position(s))

	cur.AddChild(nextVisitorNode)
	stack = append(stack, nextVisitorNode)
	seen[nextVisitorNode.Key()] = true
	return stack
}

// _, isParam := node.(*df.ParamNode) // param may have intra-procedural incoming edges
// _, isCall := node.(*df.CallNode)   // call may have inter-procedural edges
// // call argument may have inter-procedural edges only if it is nillable
// isCallArg := false
// if arg, ok := node.(*df.CallNodeArg); ok {
// 	isCallArg = lang.IsNillableType(arg.Type())
// }
// // hasIntraIncomingEdges = hasIntraIncomingEdges && !isCallArg

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
func findTrace(s *df.AnalyzerState, end *df.VisitorNode) Trace {
	trace := Trace{}
	cur := end
	for cur != nil {
		node := TraceNode{
			VisitorNode: cur,
			Pos:         cur.Node.Position(s),
			Values:      nil,
		}
		trace = append(trace, node)
		cur = cur.Prev
	}

	return trace
}

// IsStatic returns true if node is a constant value.
// TODO make this better
func IsStatic(node df.GraphNode) bool {
	switch node := node.(type) {
	case *df.CallNodeArg:
		switch node.Value().(type) {
		case *ssa.Const:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// IsInterProceduralEntryPoint returns true if cfg identifies n as a backtrace entrypoint.
func IsInterProceduralEntryPoint(state *df.AnalyzerState, ss *config.SlicingSpec, n ssa.Node) bool {
	if f, ok := n.(*ssa.Function); ok {
		pkg := lang.PackageNameFromFunction(f)
		return ss.IsBacktracePoint(config.CodeIdentifier{Package: pkg, Method: f.Name()})
	}

	return isIntraProceduralEntryPoint(state, ss, n)
}

func isSomeIntraProceduralEntryPoint(cfg *config.Config, p *pointer.Result, n ssa.Node) bool {
	return analysisutil.IsEntrypointNode(p, n, func(cid config.CodeIdentifier) bool {
		return cfg.IsSomeBacktracePoint(cid)
	})
}

func isIntraProceduralEntryPoint(state *df.AnalyzerState, ss *config.SlicingSpec, n ssa.Node) bool {
	return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, func(cid config.CodeIdentifier) bool {
		return ss.IsBacktracePoint(cid)
	})
}

func intraProceduralPassWithOnDemand(state *df.AnalyzerState, numRoutines int) {
	cfg := state.Config
	entryFuncs := []*ssa.Function{}
	for f := range state.ReachableFunctions(false, false) {
		pkg := ""
		if f.Package() != nil {
			pkg = f.Package().String()
		}
		if cfg.IsSomeBacktracePoint(config.CodeIdentifier{
			Package:  pkg,
			Method:   f.Name(),
			Receiver: "",
			Field:    "",
			Type:     "",
			Label:    "",
		}) {
			entryFuncs = append(entryFuncs, f)
		}
	}

	// shouldSummarize stores all the functions that should be summarized
	shouldSummarize := map[*ssa.Function]bool{}
	for _, entry := range entryFuncs {
		callers := allCallers(state, entry)
		for _, c := range callers {
			shouldSummarize[c.Caller.Func] = true
		}
	}

	analysis.RunIntraProceduralPass(state, numRoutines, analysis.IntraAnalysisParams{
		ShouldBuildSummary: func(_ *df.AnalyzerState, f *ssa.Function) bool {
			return shouldSummarize[f]
		},
		IsEntrypoint: isSomeIntraProceduralEntryPoint,
	})
}

func allCallers(state *df.AnalyzerState, entry *ssa.Function) []*callgraph.Edge {
	node := state.PointerAnalysis.CallGraph.Nodes[entry]
	res := make([]*callgraph.Edge, 0, len(node.In))
	for _, in := range node.In {
		if in.Caller != nil {
			res = append(res, in)
		}
	}

	return res
}

// traceNode prints trace information about node.
func traceNode(s *df.AnalyzerState, node *df.VisitorNode) {
	logger := s.Logger
	if !logger.LogsTrace() {
		return
	}
	logger.Tracef("----------------\n")
	logger.Tracef("Visiting %T node: %v\n\tat %v\n", node.Node, node.Node, node.Node.Position(s))
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
