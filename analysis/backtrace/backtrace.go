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
	"github.com/awslabs/ar-go-tools/internal/colors"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

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
	return "Trace:\n" + strings.Join(funcutil.Map(t, func(n TraceNode) string { return "\t" + n.String() }), "\n")
}

// TraceNode represents a node in the trace.
type TraceNode struct {
	df.GraphNode
	Pos    token.Position
	Values []string // TODO maybe
}

func (n TraceNode) String() string {
	if n.GraphNode == nil {
		return ""
	}

	return fmt.Sprintf("%v at %v", n.GraphNode.String(), n.Pos)
}

// Analyze runs the analysis on the program prog with the user-provided configuration config.
// If the analysis run successfully, an AnalysisResult is returned, containing all the information collected.
//
// - cfg is the configuration that determines which functions are sources, sinks and sanitizers.
//
// - prog is the built ssa representation of the program. The program must contain a main package and include all its
// dependencies, otherwise the pointer analysis will fail.
func Analyze(logger *config.LogGroup, cfg *config.Config, prog *ssa.Program) (AnalysisResult, error) {
	// Number of working routines to use in parallel. TODO: make this an option?
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	state, err := df.NewInitializedAnalyzerState(logger, cfg, prog)
	if err != nil {
		return AnalysisResult{}, err
	}

	if cfg.SummarizeOnDemand {
		logger.Infof("On-demand summarization is enabled")
		singleFunctionSummarizeOnDemand(state, cfg, numRoutines)
	} else {
		// Only build summaries for non-stdlib functions here
		analysis.RunIntraProcedural(state, numRoutines, analysis.IntraAnalysisParams{
			ShouldCreateSummary: df.ShouldCreateSummary,
			ShouldBuildSummary:  df.ShouldBuildSummary,
			IsEntrypoint:        isSingleFunctionEntrypoint,
		})
	}

	visitor := &Visitor{}
	analysis.RunInterProcedural(state, visitor, analysis.InterProceduralParams{
		IsEntrypoint: IsCrossFunctionEntrypoint,
	})

	logger.Infof(colors.Green("Found %d traces.\n"), len(visitor.Traces))

	return AnalysisResult{Graph: *state.FlowGraph, Traces: Traces(state, visitor.Traces)}, nil
}

func Traces(s *df.AnalyzerState, traces [][]df.GraphNode) []Trace {
	res := make([]Trace, 0, len(traces))
	for _, tr := range traces {
		trace := make([]TraceNode, 0, len(tr))
		for _, node := range tr {
			trace = append(trace, TraceNode{GraphNode: node, Pos: node.Position(s)})
		}
		res = append(res, trace)
	}

	return res
}

type Visitor struct {
	Traces [][]df.GraphNode
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
	logger.Infof("==> Node: %s\n", colors.Purple(entrypoint.String()))
	logger.Infof("%s %s\n", colors.Green("Found at"), pos)

	// Skip entrypoint if it is in a dependency or in the Go standard library/runtime
	// TODO make this an option in the config
	if strings.Contains(pos.Filename, "vendor") || strings.Contains(pos.Filename, runtime.GOROOT()) {
		logger.Infof("%s\n", colors.Red("Skipping..."))
		return
	}

	var trace *df.NodeTree[*df.CallNode]
	entry := df.NodeWithTrace{Node: entrypoint, Trace: trace}
	seen := make(map[string]bool)
	goroutines := make(map[*ssa.Go]bool)
	stack := []*visitorNode{{NodeWithTrace: entry, prev: nil, depth: 0}}

	var elt *visitorNode
	for len(stack) != 0 {
		elt = stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		logger.Tracef("----------------\n")
		logger.Tracef("Visiting %T node: %v\n\tat %v\n", elt.Node, elt.Node, elt.Node.Position(s))
		logger.Tracef("Element trace: %s\n", elt.Trace.String())
		logger.Tracef("Element closure trace: %s\n", elt.ClosureTrace.String())
		logger.Tracef("Element backtrace: %v\n", findTrace(elt))

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			if !s.Config.SummarizeOnDemand {
				logger.Tracef("%s: summary has not been built for %s.",
					colors.Yellow("WARNING"),
					colors.Yellow(elt.Node.Graph().Parent.Name()))

				// In that case, continue as there is no information on data flow
				continue
			}

			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			if err := df.RunIntraProcedural(s, elt.Node.Graph()); err != nil {
				panic(fmt.Errorf("failed to run the intra-procedural analysis: %v", err))
			}
		}

		// Base case: add the trace if there are no more (intra- or inter-procedural) incoming edges from the node
		if isBaseCase(elt.Node, s.Config) {
			t := findTrace(elt)
			v.Traces = append(v.Traces, t)

			logger.Tracef("Base case reached...")
			logger.Tracef("Adding trace: %v\n", t)
			continue
		}

		switch graphNode := elt.Node.(type) {
		// Data flows from the function parameter to the corresponding function call argument at the call site.
		case *df.ParamNode:
			if elt.prev.Node.Graph() != graphNode.Graph() {
				// Flows inside the function body. The data propagates to other locations inside the function body
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
				}
			}

			// If the parameter was visited from an inter-procedural edge (i.e. from a call argument node), then data
			// must flow back to that argument.
			if elt.Trace.Len() > 0 && elt.Trace.Label != nil {
				callSite := elt.Trace.Label
				if err := df.CheckIndex(s, graphNode, callSite, "[Context] No argument at call site"); err != nil {
					s.AddError("argument at call site "+graphNode.String(), err)
					panic("no arg at call site")
				} else {
					arg := callSite.Args()[graphNode.Index()]
					stack = addNext(s, stack, seen, elt, arg, elt.Trace, elt.ClosureTrace)
					continue
				}
			}

			// No context: the value must always flow back to all call sites

			// Summary graph callsite information may be incomplete so use the pointer analysis to fill in
			// any missing information
			// This should only be done for functions that have not been pre-summarized
			if s.Config.SummarizeOnDemand && !graphNode.Graph().IsPreSummarized {
				df.BuildDummySummariesFromCallgraph(s, elt.NodeWithTrace, IsCrossFunctionEntrypoint)
			}

			callSites := graphNode.Graph().Callsites
			for _, callSite := range callSites {
				if err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
					s.AddError("argument at call site "+graphNode.String(), err)
					panic("no arg")
				} else {
					arg := callSite.Args()[graphNode.Index()]
					stack = addNext(s, stack, seen, elt, arg, elt.Trace, elt.ClosureTrace)
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
							//logger.Warnf("callsite has no callee: %v\n", callSite)
							//break
						}

						// the callee summary may not have been created yet
						if callSite.CalleeSummary == nil {
							callSite.CalleeSummary = df.NewSummaryGraph(s, callSite.Callee(), df.GetUniqueFunctionId(),
								isSingleFunctionEntrypoint, nil)
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
					x := callSite.CalleeSummary.Params[param]
					stack = addNext(s, stack, seen, elt, x, elt.Trace.Add(callSite), elt.ClosureTrace)
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
				for out := range graphNode.Out() {
					stack = addNext(s, stack, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}

			// We pop the call from the trace (callstack) when exiting the callee and returning to the caller
			var tr *df.NodeTree[*df.CallNode]
			if elt.Trace != nil {
				tr = elt.Trace.Parent
			}

			// Check if the previous node was a parameter coming from the same function (recursive call)
			prevIsRecursiveParam := false
			if elt.prev != nil {
				if param, ok := elt.prev.Node.(*df.ParamNode); ok {
					prevIsRecursiveParam = param.Graph() == callSite.Graph()
				}
			}
			// Data flows backwards from the argument within the function
			if elt.prev == nil || callSite.Graph() != elt.prev.Node.Graph() || prevIsRecursiveParam {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, tr, elt.ClosureTrace)
				}
			}

			// Arg base case:
			// - matching parameter was not detected, or
			// - value is not bound, and
			// - no more incoming edges from the arg
			if prevStackLen == len(stack) {
				t := findTrace(elt)
				v.Traces = append(v.Traces, t)
				logger.Tracef("CallNodeArg base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the return statement.
		case *df.ReturnValNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
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
				graphNode.CalleeSummary = df.BuildSummary(s, graphNode.Callee(), isSingleFunctionEntrypoint)
			}

			if graphNode.CalleeSummary != nil {
				for _, rets := range graphNode.CalleeSummary.Returns {
					for _, ret := range rets {
						// We add the caller's node to the trace (callstack) when flowing to the callee's return node
						stack = addNext(s, stack, seen, elt, ret, elt.Trace.Add(graphNode), elt.ClosureTrace)
					}
				}
			} else {
				panic(fmt.Errorf("node's callee summary is nil: %v", graphNode))
			}

			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

			// Call node base case:
			// - no new (non-visited) matching return, and
			// - no more incoming edges from the call
			if prevStackLen == len(stack) {
				t := findTrace(elt)
				v.Traces = append(v.Traces, t)
				logger.Tracef("CallNode base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		// Data flows backwards within the function from the synthetic node.
		case *df.SyntheticNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

		// From a global write node, data flows backwards intra-procedurally.
		// From a read location, backwards data flow follows ALL the write locations of the node.
		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
				}
			} else {
				if s.Config.SummarizeOnDemand {
					logger.Tracef("Global %v SSA instruction: %v\n", graphNode, graphNode.Instr())
					for f := range s.ReachableFunctions(false, false) {
						if lang.FnWritesTo(f, graphNode.Global.Value()) {
							logger.Tracef("Global %v written in function: %v\n", graphNode, f)
							df.BuildSummary(s, f, isSingleFunctionEntrypoint)
						}
					}
					//s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				}

				for x := range graphNode.Global.WriteLocations {
					stack = addNext(s, stack, seen, elt, x, nil, elt.ClosureTrace)
				}
			}

		case *df.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}
			closureNode := graphNode.ParentNode()

			if s.Config.SummarizeOnDemand && closureNode.ClosureSummary == nil {
				closureNode.ClosureSummary = df.BuildSummary(s, closureNode.Instr().Fn.(*ssa.Function),
					isSingleFunctionEntrypoint)
				//s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				logger.Tracef("closure summary parent: %v\n", closureNode.ClosureSummary.Parent)
			}

			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				stack = addNext(s, stack, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				panic(fmt.Errorf("no free variable matching bound variable in %s at position %d",
					closureNode.ClosureSummary.Parent.String(), graphNode.Index()))
				//s.AddError(
				//	fmt.Sprintf("no free variable matching bound variable in %s",
				//		closureNode.ClosureSummary.Parent.String()),
				//	fmt.Errorf("at position %d", graphNode.Index()))
			}

		case *df.FreeVarNode:
			prevStackLen := len(stack)

			// Flows inside the function
			if elt.prev.Node.Graph() != graphNode.Graph() {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil {
				//logger.Tracef("Closure trace: %v", elt.ClosureTrace.Label)
				//closureSummary := elt.ClosureTrace.Label.Graph()
				//if !closureSummary.Constructed {
				//	closureSummary = df.BuildSummary(s, elt.ClosureTrace.Label.Graph().Parent, isSingleFunctionEntrypoint)
				//	s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				//}
				// Flow to the matching bound variables at the make closure site from the closure trace
				bvs := elt.ClosureTrace.Label.BoundVars()
				if len(bvs) == 0 {
					panic("no bound vars")
				}
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					stack = addNext(s, stack, seen, elt, bv, elt.Trace, elt.ClosureTrace.Parent)
				} else {
					panic(fmt.Errorf("no bound variable matching free variable in %s at position %d",
						elt.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index()))
					// s.AddError(
					// 	fmt.Sprintf("no bound variable matching free variable in %s",
					// 		elt.ClosureTrace.Label.ClosureSummary.Parent.String()),
					// 	fmt.Errorf("at position %d", graphNode.Index()))
				}
			} else {
				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					// Summarize the free variable's closure's parent function if there is one
					f := graphNode.Graph().Parent.Parent()
					if f != nil {
						df.BuildSummary(s, f, isSingleFunctionEntrypoint)
					}
					// This is needed to get the referring make closures outside the function
					s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
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
						stack = addNext(s, stack, seen, elt, bv, elt.Trace, nil)
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
				t := findTrace(elt)
				v.Traces = append(v.Traces, t)
				logger.Tracef("Free var base case reached...")
				logger.Tracef("Adding trace: %v\n", t)
			}

		case *df.ClosureNode:
			// Data flows backwards from the bound variables of the closure
			for _, b := range graphNode.BoundVars() {
				stack = addNext(s, stack, seen, elt, b, elt.Trace, elt.ClosureTrace)
			}

		case *df.BoundLabelNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

		default:
			panic(fmt.Errorf("unhandled graph node type: %T", graphNode))
		}
	}
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

type visitorNode struct {
	df.NodeWithTrace
	prev  *visitorNode
	depth int
}

func (v *visitorNode) String() string {
	return fmt.Sprintf("{%s}", v.Node)
}

// findTrace returns a slice of all the nodes in the trace starting from end.
func findTrace(end *visitorNode) []df.GraphNode {
	nodes := []df.GraphNode{}
	cur := end
	for cur != nil {
		nodes = append(nodes, cur.Node)
		cur = cur.prev
	}

	return nodes
}

// addNext adds next to stack, setting cur as the previous node and checking that node with the
// trace has not been seen before. Returns the new stack.
func addNext(s *df.AnalyzerState,
	stack []*visitorNode,
	seen map[string]bool,
	cur *visitorNode,
	next df.GraphNode,
	trace *df.NodeTree[*df.CallNode],
	closureTrace *df.NodeTree[*df.ClosureNode]) []*visitorNode {

	newNode := df.NodeWithTrace{Node: next, Trace: trace, ClosureTrace: closureTrace}

	s.Logger.Tracef("Adding %v at %v\n", next, next.Position(s))
	s.Logger.Tracef("\ttrace: %v\n", trace)
	s.Logger.Tracef("\tclosure-trace: %v\n", closureTrace)
	s.Logger.Tracef("\tseen? %v\n", seen[newNode.Key()])
	s.Logger.Tracef("\tlasso? %v\n", trace.GetLassoHandle() != nil)
	s.Logger.Tracef("\tdepth: %v\n", cur.depth)

	// Stop conditions
	if seen[newNode.Key()] || trace.GetLassoHandle() != nil || cur.depth > s.Config.MaxDepth {
		s.Logger.Tracef("\tstopping...")
		return stack
	}

	newVis := &visitorNode{
		NodeWithTrace: newNode,
		prev:          cur,
		depth:         cur.depth + 1,
	}
	stack = append(stack, newVis)
	seen[newNode.Key()] = true
	return stack
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

// IsCrossFunctionEntrypoint returns true if cfg identifies n as a backtrace entrypoint.
func IsCrossFunctionEntrypoint(cfg *config.Config, n ssa.Node) bool {
	if f, ok := n.(*ssa.Function); ok {
		pkg := lang.PackageNameFromFunction(f)
		return cfg.IsBacktracePoint(config.CodeIdentifier{Package: pkg, Method: f.Name()})
	}

	return isSingleFunctionEntrypoint(cfg, n)
}

func isSingleFunctionEntrypoint(cfg *config.Config, n ssa.Node) bool {
	return analysisutil.IsEntrypointNode(cfg, n, config.Config.IsBacktracePoint)
}

func singleFunctionSummarizeOnDemand(state *df.AnalyzerState, cfg *config.Config, numRoutines int) {
	entryFuncs := []*ssa.Function{}
	for f := range df.CallGraphReachable(state.PointerAnalysis.CallGraph, false, false) {
		pkg := ""
		if f.Package() != nil {
			pkg = f.Package().String()
		}
		if cfg.IsBacktracePoint(config.CodeIdentifier{
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
	// compute all the reachable functions
	state.ReachableFunctions(false, true)
	for _, entry := range entryFuncs {
		callers := allCallers(state, entry)
		for _, c := range callers {
			if df.ShouldCreateSummary(c.Caller.Func) {
				shouldSummarize[c.Caller.Func] = true
			}
		}
	}

	analysis.RunIntraProcedural(state, numRoutines, analysis.IntraAnalysisParams{
		ShouldCreateSummary: func(f *ssa.Function) bool {
			return shouldSummarize[f] // these concurrent map reads are safe because they are not written to
		},
		ShouldBuildSummary: func(_ *df.AnalyzerState, f *ssa.Function) bool {
			return shouldSummarize[f]
		},
		IsEntrypoint: isSingleFunctionEntrypoint,
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

func findCallsites(state *df.AnalyzerState, f *ssa.Function) []ssa.CallInstruction {
	node := state.PointerAnalysis.CallGraph.Nodes[f]
	res := make([]ssa.CallInstruction, 0, len(node.In))
	for _, in := range node.In {
		if in.Site != nil {
			res = append(res, in.Site)
		}
	}

	return res
}

// addCallToCallsites adds c to callSites if it is in summary's callees.
func addCallToCallsites(s *df.AnalyzerState, summary *df.SummaryGraph, c ssa.CallInstruction, callSites map[ssa.CallInstruction]*df.CallNode) {
	for instr, f2n := range summary.Callees {
		if instr == c {
			for _, callNode := range f2n {
				s.Logger.Tracef("adding call instruction %v -> %v to callsites\n", instr, callNode)
				callSites[instr] = callNode
			}
		}
	}
}

// isConst returns true if node represents a constant value.
// This is only implemented for CallNodeArg for now.
func isConst(node df.GraphNode) bool {
	switch n := node.(type) {
	case *df.CallNodeArg:
		_, ok := n.Value().(*ssa.Const)
		return ok
	default:
		return false
	}
}
