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
	"log"
	"runtime"
	"strings"

	"go/token"

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
	Graph df.CrossFunctionFlowGraph

	// Traces represents all the paths where data flows out from the analysis entrypoints.
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
func Analyze(logger *log.Logger, cfg *config.Config, prog *ssa.Program) (AnalysisResult, error) {
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
		singleFunctionSummarizeOnDemand(state, cfg, numRoutines)
	} else {
		// Only build summaries for non-stdlib functions here
		analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			AnalyzerState:       state,
			NumRoutines:         numRoutines,
			ShouldCreateSummary: df.ShouldCreateSummary,
			ShouldBuildSummary:  df.ShouldBuildSummary,
			IsEntrypoint:        isSingleFunctionEntrypoint,
		})
	}

	visitor := &Visitor{}
	analysis.RunCrossFunction(analysis.RunCrossFunctionArgs{
		AnalyzerState: state,
		Visitor:       visitor,
		IsEntrypoint:  IsCrossFunctionEntrypoint,
	})

	logger.Printf(colors.Green("Found %d traces.\n"), len(visitor.Traces))

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

// Visit runs a cross-function backwards analysis to add any detected backtraces to v.Traces.
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

func (v *Visitor) visit(s *df.AnalyzerState, entrypoint *df.CallNodeArg) {
	pos := entrypoint.Position(s)
	if !pos.IsValid() {
		pos = entrypoint.ParentNode().Position(s)
	}

	logger := s.Logger
	logger.Printf("\n%s ENTRYPOINT %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Printf("==> Node: %s\n", colors.Purple(entrypoint.String()))
	logger.Printf("%s %s\n", colors.Green("Found at"), pos)

	// Skip entrypoint if it is in a dependency
	// TODO make this an option in the config
	if strings.Contains(pos.Filename, "vendor") {
		logger.Printf("%s\n", colors.Red("Skipping..."))
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

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			if s.Config.Verbose {
				logger.Printf("%s: summary has not been built for %s.",
					colors.Yellow("WARNING"),
					colors.Yellow(elt.Node.Graph().Parent.Name()))
			}
			// In that case, continue as there is no information on data flow
			continue
		}

		if s.Config.Verbose {
			logger.Printf("----------------\n")
			logger.Printf("Visiting %T node: %v\n\tat %v\n", elt.Node, elt.Node, elt.Node.Position(s))
			logger.Printf("Element trace: %s\n", elt.Trace.String())
		}

		// Base case: add the trace if there are no more (intra- or inter-procedural) incoming edges from the node
		if isBaseCase(elt.Node) {
			t := findTrace(elt)
			v.Traces = append(v.Traces, t)
			if s.Config.Verbose {
				logger.Println("Base case reached...")
			}
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

			// The value must always flow back to all call sites

			// Summary graph callsite information may be incomplete so use the pointer analysis to fill in
			// any missing information
			// This should only be done for functions that have not been pre-summarized
			if s.Config.SummarizeOnDemand && !graphNode.Graph().IsPreSummarized {
				df.BuildSummariesFromCallgraph(s, elt.NodeWithTrace, IsCrossFunctionEntrypoint)
			}

			if s.Config.SummarizeOnDemand {
				if elt.Trace != nil {
					fn := elt.Trace.Label.CallSite().Parent()
					if _, ok := s.FlowGraph.Summaries[fn]; !ok {
						if s.Config.Verbose {
							logger.Printf("trace label parent not summarized: %v\n", fn)
						}
						df.BuildSummary(s, fn, isSingleFunctionEntrypoint)
						s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
					}
				}

				if elt.ClosureTrace != nil {
					fn := elt.ClosureTrace.Label.Instr().Fn.(*ssa.Function)
					if _, ok := s.FlowGraph.Summaries[fn]; !ok {
						if s.Config.Verbose {
							logger.Printf("closure trace label not summarized: %v\n", fn)
						}
						df.BuildSummary(s, fn, isSingleFunctionEntrypoint)
						s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
					}
				}
			}

			callSites := graphNode.Graph().Callsites
			if s.Config.SummarizeOnDemand && elt.Trace != nil {
				// the trace label callee may not be in the summary's callsites
				callInstrs := findCallsites(s, elt.Trace.Label.Callee())
				for _, c := range callInstrs {
					if _, ok := callSites[c]; !ok {
						if s.Config.Verbose {
							logger.Printf("callsite %v not found in callsites\n", c)
						}

						if summary, ok := s.FlowGraph.Summaries[c.Parent()]; ok {
							if s.Config.Verbose {
								logger.Printf("summary for %v found in FlowGraph", c.Parent())
							}
							addCallToCallsites(s, summary, c, callSites)
						} else {
							if s.Config.Verbose {
								logger.Printf("summary for %v NOT found in FlowGraph", c.Parent())
							}
							summary = df.BuildSummary(s, c.Parent(), isSingleFunctionEntrypoint)
							s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
							addCallToCallsites(s, summary, c, callSites)
						}
					}
				}
			}

			for _, callSite := range callSites {
				if err := analysisutil.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
					s.AddError("argument at call site "+graphNode.String(), err)
				} else {
					arg := callSite.Args()[graphNode.Index()]
					// If the argument is not part of the calling context, don't add it to the visitor stack.
					// This is needed for context-sensitivity.
					if elt.Trace.Len() > 0 && elt.Trace.Label != arg.ParentNode() {
						if s.Config.Verbose {
							logger.Printf("arg is not part of calling context in callsite: %v. skipping...\n", callSite)
							logger.Printf("\tparent node: %v\n", arg.ParentNode())
							logger.Printf("\ttrace label: %v\n", elt.Trace.Label)
						}
						continue
					}

					stack = addNext(s, stack, seen, elt, arg, elt.Trace, elt.ClosureTrace)
				}
			}

		// Data flows backwards within the function from the function call argument.
		case *df.CallNodeArg:
			callSite := graphNode.ParentNode()

			if callSite.CalleeSummary == nil || !callSite.CalleeSummary.Constructed { // this function has not been summarized
				if s.Config.SummarizeOnDemand {
					if callSite.Callee() == nil {
						logger.Printf("callsite has no callee: %v\n", callSite)
						break
					}

					df.BuildSummary(s, callSite.Callee(), isSingleFunctionEntrypoint)
					s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				} else {
					analysisutil.PrintMissingSummaryMessage(s, callSite)
					break
				}
			}

			if s.Config.SummarizeOnDemand && strings.Contains(callSite.ParentName(), "$thunk") {
				// HACK: Make the callsite's callee summary point to the actual function summary, not the "thunk" summary
				// This is needed because "thunk" summaries can be incomplete
				// TODO Is there a better way to identify a function thunk?
				logger.Printf("callsite parent is a function \"thunk\": %v\n", callSite.ParentName())
				calleeSummary := df.BuildSummary(s, callSite.Callee(), isSingleFunctionEntrypoint)
				s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				callSite.CalleeSummary = calleeSummary
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			// Data flows backwards from the argument to the corresponding parameter
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				x := callSite.CalleeSummary.Params[param]
				stack = addNext(s, stack, seen, elt, x, elt.Trace.Add(callSite), elt.ClosureTrace)
			} else {
				s.AddError(
					fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
					fmt.Errorf("position %d", graphNode.Index()))
			}

			// We pop the call from the trace (callstack) when exiting the callee and returning to the caller
			var tr *df.NodeTree[*df.CallNode]
			if elt.Trace != nil {
				tr = elt.Trace.Parent
			}
			// Data flows backwards from the argument within the function
			if elt.prev == nil || callSite.Graph() != elt.prev.Node.Graph() {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, tr, elt.ClosureTrace)
				}
			}

		// Data flows backwards within the function from the return statement.
		case *df.ReturnValNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

		// Data flows from the function call to the called function's return statement.
		// It also flows backwards within the parent function.
		case *df.CallNode:
			analysisutil.CheckNoGoRoutine(s, goroutines, graphNode)
			if s.Config.SummarizeOnDemand && graphNode.CalleeSummary == nil {
				logger.Printf("summary for callee is nil: %v\n", graphNode.Callee().String())
				graphNode.CalleeSummary = df.BuildSummary(s, graphNode.Callee(), isSingleFunctionEntrypoint)
				s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
			}

			if graphNode.CalleeSummary != nil {
				for _, rets := range graphNode.CalleeSummary.Returns {
					for _, ret := range rets {
						// We add the caller's node to the trace (callstack) when flowing to the callee's return node
						stack = addNext(s, stack, seen, elt, ret, elt.Trace.Add(graphNode), elt.ClosureTrace)
					}
				}
			} else {
				panic(fmt.Errorf("node's callee summary is nil: %v", graphNode.Callee().String()))
			}

			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

		// Data flows backwards within the function from the synthetic node.
		case *df.SyntheticNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

		// From a global write node, data flows backwards to ALL the locations where the global is read.
		// From a read location, backwards data flow follows the write locations of the node.
		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
				}
			} else {
				if s.Config.SummarizeOnDemand {
					for f := range s.ReachableFunctions(false, false) {
						if lang.FnWritesTo(f, graphNode.Global.Value()) {
							if s.Config.Verbose {
								logger.Printf("Global %v written in function: %v\n", graphNode, f)
							}
							df.BuildSummary(s, f, isSingleFunctionEntrypoint)
						}
					}
					s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
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
				closureNode.ClosureSummary = df.BuildSummary(s, closureNode.Instr().Fn.(*ssa.Function), isSingleFunctionEntrypoint)
				s.FlowGraph.BuildGraph(IsCrossFunctionEntrypoint)
				logger.Printf("closure summary parent: %v\n", closureNode.ClosureSummary.Parent)
			}

			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				stack = addNext(s, stack, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				s.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s",
						closureNode.ClosureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
			}

		case *df.FreeVarNode:
			// Flows inside the function
			if elt.prev.Node.Graph() != graphNode.Graph() {
				for in := range graphNode.In() {
					stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil {
				// Flow to the matching bound variables at the make closure site from the closure trace
				bvs := elt.ClosureTrace.Label.BoundVars()
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					stack = addNext(s, stack, seen, elt, bv, elt.Trace, elt.ClosureTrace.Parent)
				} else {
					s.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							elt.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
				}
			} else {
				// If there is no closure trace, there is no calling context so
				// flow to every make closure site in the graph
				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						stack = addNext(s, stack, seen, elt, bv, elt.Trace, nil)
					} else {
						s.AddError(
							fmt.Sprintf("[No Context] no bound variable matching free variable in %s",
								makeClosureSite.ClosureSummary.Parent.String()),
							fmt.Errorf("at position %d", graphNode.Index()))
					}

				}
			}

		case *df.ClosureNode:
			for in := range graphNode.In() {
				stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
			}

			// Data flows backwards from the bound variables of the closure
			for _, b := range graphNode.BoundVars() {
				stack = addNext(s, stack, seen, elt, b, elt.Trace, elt.ClosureTrace)
			}

		// case *df.BoundLabelNode:
		// 	// TODO test this
		// 	for in := range graphNode.In() {
		// 		stack = addNext(s, stack, seen, elt, in, elt.Trace, elt.ClosureTrace)
		// 	}

		default:
			panic(fmt.Errorf("unhandled graph node type: %T", graphNode))
		}
	}
}

// isBaseCase returns true if the analysis should not analyze node any further.
func isBaseCase(node df.GraphNode) bool {
	hasIntraIncomingEdges := len(node.In()) != 0
	canHaveInterIncomingEdges := func(node df.GraphNode) bool {
		if global, ok := node.(*df.AccessGlobalNode); ok {
			return (global.IsWrite && len(global.In()) > 0) || (!global.IsWrite && len(global.Global.WriteLocations) > 0)
		}
		_, isParam := node.(*df.ParamNode)       // param should not have intra-procedural incoming edges
		_, isCall := node.(*df.CallNode)         // call may have inter-procedural edges
		_, isClosure := node.(*df.ClosureNode)   // closure data flows backwards to its bound variables
		_, isBoundVar := node.(*df.BoundVarNode) // bound variables may flow to free variables
		return isParam || isCall || isClosure || isBoundVar
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

	if s.Config.Verbose {
		s.Logger.Printf("Adding %v\n", next)
		s.Logger.Printf("\ttrace: %v\n", trace)
		s.Logger.Printf("\tclosure-trace: %v\n", closureTrace)
		s.Logger.Printf("\tseen? %v\n", seen[newNode.Key()])
		s.Logger.Printf("\tlasso? %v\n", trace.IsLasso())
		s.Logger.Printf("\tdepth: %v\n", cur.depth)
	}

	// Stop conditions
	if seen[newNode.Key()] || trace.IsLasso() || cur.depth > s.Config.MaxDepth {
		if s.Config.Verbose {
			s.Logger.Printf("\tstopping...")
		}

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
	return analysisutil.IsEntrypointNode(cfg, n, (config.Config).IsBacktracePoint)
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

	analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		AnalyzerState: state,
		NumRoutines:   numRoutines,
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
				if s.Config.Verbose {
					s.Logger.Printf("adding call instruction %v -> %v to callsites\n", instr, callNode)
				}
				callSites[instr] = callNode
			}
		}
	}
}
