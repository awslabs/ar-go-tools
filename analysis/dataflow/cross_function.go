// Package dataflow contains abstractions for reasoning about data flow within programs.
package dataflow

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/format"
	"github.com/awslabs/argot/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

// Visitor represents a visitor that runs a cross-function analysis from entrypoint.
type Visitor interface {
	Visit(c *Cache, entrypoint NodeWithTrace)
}

// CrossFunctionFlowGraph represents a cross-function data flow graph.
type CrossFunctionFlowGraph struct {
	Summaries     map[*ssa.Function]*SummaryGraph
	cache         *Cache
	built         bool
	ForwardEdges  map[GraphNode]map[GraphNode]bool           // forward edges between nodes belonging to different subgraphs (cross-function version of (GraphNode).Out)
	BackwardEdges map[GraphNode]map[GraphNode]bool           // backward edges between nodes belonging to different subgraphs (cross-function version of (GraphNode).In)
	Globals       map[*GlobalNode]map[*AccessGlobalNode]bool // edges between global nodes and the nodes that access the global
}

// NewCrossFunctionFlowGraph returns a new non-built cross function flow graph.
func NewCrossFunctionFlowGraph(summaries map[*ssa.Function]*SummaryGraph, cache *Cache) CrossFunctionFlowGraph {
	return CrossFunctionFlowGraph{
		Summaries:     summaries,
		cache:         cache,
		built:         false,
		ForwardEdges:  make(map[GraphNode]map[GraphNode]bool),
		BackwardEdges: make(map[GraphNode]map[GraphNode]bool),
	}
}

func (g *CrossFunctionFlowGraph) IsBuilt() bool {
	return g.built
}

// Print prints each of the function summaries in the graph.
func (g *CrossFunctionFlowGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	fmt.Fprintf(w, "\tcompound=true;\n") // visually group subgraphs together
	for _, summary := range g.Summaries {
		summary.Print(false, w)
	}
	const forwardColor = "\"#1cf4a3\""  // green
	const backwardColor = "\"#dc143c\"" // red
	const fmtColorEdge = "%s -> %s [color=%s];\n"
	for src, dsts := range g.ForwardEdges {
		for dst := range dsts {
			fmt.Fprintf(w, fmtColorEdge, escape(src.String()), escape(dst.String()), forwardColor)
		}
	}
	for dst, srcs := range g.BackwardEdges {
		for src := range srcs {
			fmt.Fprintf(w, fmtColorEdge, escape(dst.String()), escape(src.String()), backwardColor)
		}
	}

	for global, accesses := range g.Globals {
		for access := range accesses {
			// write is an edge from global <- access, read is an edge from global -> access
			if access.IsWrite {
				fmt.Fprintf(w, fmtColorEdge, escape(access.String()), escape(global.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escape(global.String()), escape(access.String()), backwardColor)
			} else {
				fmt.Fprintf(w, fmtColorEdge, escape(global.String()), escape(access.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escape(access.String()), escape(global.String()), backwardColor)
			}
		}
	}

	fmt.Fprintf(w, "}\n")
}

// InsertSummaries inserts all the summaries from g2 in g
func (g *CrossFunctionFlowGraph) InsertSummaries(g2 CrossFunctionFlowGraph) {
	for f, sum := range g2.Summaries {
		g.Summaries[f] = sum
	}
}

type NodeWithTrace struct {
	Node         GraphNode
	Trace        *NodeTree[*CallNode]
	ClosureTrace *NodeTree[*ClosureNode]
}

// BuildGraph builds the cross function flow graph by connecting summaries together
func (g *CrossFunctionFlowGraph) BuildGraph() {
	g.cache.Logger.Println("Building cross-function flow graph...")
	c := g.cache
	logger := c.Logger
	// Open a file to output summaries
	summariesFile := openSummaries(c)
	if summariesFile != nil {
		defer summariesFile.Close()
	}

	// Build the cross-function data flow graph: link all the summaries together
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
		}
		if summariesFile != nil {
			_, _ = summariesFile.WriteString(fmt.Sprintf("%s:\n", summary.Parent.String()))
			summary.Print(false, summariesFile)
			_, _ = summariesFile.WriteString("\n")
		}
		for _, callNodes := range summary.Callees {
			for _, node := range callNodes {
				if node.Callee() != nil && node.CalleeSummary == nil {
					var calleeSummary *SummaryGraph

					if node.callee.Type != InterfaceContract {
						calleeSummary = findCalleeSummary(node.Callee(), g.Summaries)
					}
					// If it's not in the generated summaries, try to fetch it from predefined summaries or interface
					// contracts
					if calleeSummary == nil {
						if calleeSummary = g.cache.LoadInterfaceContractSummary(node); calleeSummary != nil {
							if g.cache.Config.Verbose {
								logger.Printf("Loaded %s from interface contracts.\n",
									node.CallSite().Common().String())
							}
							g.Summaries[node.Callee()] = calleeSummary
						} else if calleeSummary = LoadPredefinedSummary(node.Callee()); calleeSummary != nil {
							if g.cache.Config.Verbose {
								logger.Printf("Loaded %s from summaries.\n", node.Callee().String())
							}
							g.Summaries[node.Callee()] = calleeSummary
						}
					}
					// Add edge from callee to caller (adding a call site in the callee)
					if calleeSummary != nil {
						if x := calleeSummary.Callsites[node.CallSite()]; x == nil {
							calleeSummary.Callsites[node.CallSite()] = node
						}
					} else {
						summaryNotFound(g, node)
					}
					node.CalleeSummary = calleeSummary // nil is safe
				}
			}
		}

		for _, closureNode := range summary.CreatedClosures {
			if closureNode.instr != nil {
				closureSummary := findClosureSummary(closureNode.instr, g.Summaries)

				// Add edge from created closure summary to creator
				if closureSummary != nil {
					closureSummary.ReferringMakeClosures[closureNode.instr] = closureNode
				}
				closureNode.ClosureSummary = closureSummary // nil is safe
			}
		}
	}
	// Change the built flag to true
	g.built = true
}

func (g *CrossFunctionFlowGraph) RunCrossFunctionPass(visitor Visitor, isEntryPoint func(*config.Config, *ssa.Function) bool) {
	var entryFuncs []*SummaryGraph
	var entryPoints []NodeWithTrace

	for _, summary := range g.Summaries {
		// Identify the entry points for that function: all the call sites that are entrypoints
		// and all the synthetic nodes in the function body.
		for _, snode := range summary.SyntheticNodes {
			entry := NodeWithTrace{Node: snode, Trace: nil}
			entryPoints = append(entryPoints, entry)
		}
		if isEntryPoint(g.cache.Config, summary.Parent) {
			entryFuncs = append(entryFuncs, summary)
		}
	}

	for _, summary := range entryFuncs {
		for _, node := range summary.Callsites {
			entry := NodeWithTrace{node, nil, nil}
			entryPoints = append(entryPoints, entry)
		}
	}

	g.cache.Logger.Printf("--- # of analysis entrypoints: %d ---\n", len(entryPoints))

	// Run the analysis for every entrypoint. We may be able to change this to run the analysis for all entrypoints
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitor.Visit(g.cache, entry)
	}
}

// CrossFunctionPass runs the pass on the cross-function flow graph.
// Most of the logic is in visitor that is called for
// each possible source node identified.
//
// This function does nothing if there are no summaries
// (i.e. `len(g.summaries) == 0`)
// or if `cfg.SkipInterprocedural` is set to true.
func (g *CrossFunctionFlowGraph) CrossFunctionPass(c *Cache, visitor Visitor, isEntryPoint func(*config.Config, *ssa.Function) bool) {
	// Skip the pass if user configuration demands it
	if c.Config.SkipInterprocedural || len(g.Summaries) == 0 {
		c.Logger.Printf("Skipping cross-function pass: config.SkipInterprocedural=%v, len(summaries)=%d\n",
			c.Config.SkipInterprocedural, len(g.Summaries))
		return
	}

	// Build the inter-procedural flow graph
	g.BuildGraph()

	// Open the coverage file if specified in configuration
	coverage := openCoverage(c)
	if coverage != nil {
		defer coverage.Close()
	}

	// Run the analysis
	g.RunCrossFunctionPass(visitor, isEntryPoint)
}

// VisitorNode represents a node in the cross-function dataflow graph to be visited.
type VisitorNode struct {
	NodeWithTrace
	ParamStack *ParamStack
	Prev       *VisitorNode
	Depth      int
}

// ParamStack represents a stack of parameters.
type ParamStack struct {
	Param *ParamNode
	Prev  *ParamStack
}

// Add adds p to the stack.
func (ps *ParamStack) Add(p *ParamNode) *ParamStack {
	return &ParamStack{Param: p, Prev: ps}
}

// Parent returns the previous param in the stack.
func (ps *ParamStack) Parent() *ParamStack {
	if ps == nil {
		return nil
	} else {
		return ps.Prev
	}
}

// CrossFunctionGraphVisitor represents a visitor that builds the cache's
// FlowGraph.
type CrossFunctionGraphVisitor struct{}

// Visit is a SourceVisitor that builds adds edges between the
// individual single-function dataflow graphs reachable from source.
// This visitor must be called for every entrypoint in the program to build a
// complete dataflow graph.
func (v CrossFunctionGraphVisitor) Visit(c *Cache, entrypoint NodeWithTrace) {
	que := []*VisitorNode{{NodeWithTrace: entrypoint, ParamStack: nil, Prev: nil, Depth: 0}}
	seen := make(map[NodeWithTrace]bool)
	logger := c.Logger

	// Search from path candidates in the cross-function flow graph from sources to sinks
	// TODO: optimize call stack
	// TODO: set of visited nodes is not handled properly right now. We should revisit some nodes,
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			if c.Config.Verbose {
				logger.Printf("%s: summary has not been built for %s.",
					format.Yellow("WARNING"),
					format.Yellow(elt.Node.Graph().Parent.Name()))
			}
			// In that case, continue as there is no information on data flow
			continue
		}

		switch graphNode := elt.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *ParamNode:
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if elt.Trace != nil {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				callSite := elt.Trace.Label
				if err := checkIndex(c, graphNode, callSite, "Argument at call site"); err != nil {
					c.AddError(err)
				} else {
					// Follow taint on matching argument at call site
					arg := callSite.Args()[graphNode.Index()]
					if arg != nil {
						que = addNext(c, que, seen, elt, arg, elt.Trace.Parent, elt.ClosureTrace)

						addEdge(c.FlowGraph, arg, graphNode)
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if err := checkIndex(c, graphNode, callSite, "Argument at call site"); err != nil {
						c.AddError(err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						for x := range callSiteArg.Out() {
							que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
						}

						addEdge(c.FlowGraph, callSiteArg, graphNode)
					}
				}
			}
		// This is a call site argument. We have reached this either returning from a call, from the callee's parameter
		// node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children and to the callee's
		// parameters
		case *CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			// checkNoGoRoutine(c, goroutines, callSite)

			if callSite.CalleeSummary == nil { // this function has not been summarized
				printMissingSummaryMessage(c, callSite)
				break
			}

			if !callSite.CalleeSummary.Constructed {
				printWarningSummaryNotConstructed(c, callSite)
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				x := callSite.CalleeSummary.Params[param]
				que = addNext(c, que, seen, elt, x, elt.Trace.Add(callSite), elt.ClosureTrace)
				addEdge(c.FlowGraph, graphNode, x)
			} else {
				c.AddError(fmt.Errorf("no parameter matching argument at position %d in %s",
					graphNode.Index(), callSite.CalleeSummary.Parent.String()))
			}

			if elt.Prev == nil || callSite.Graph() != elt.Prev.Node.Graph() {
				// We are done with propagating to the callee's parameters. Next, we need to handle
				// the flow inside the caller function: the outgoing edges computed for the summary
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *ReturnNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if caller := UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); caller != nil {
				// This function was called: the value flows back to the call site only
				addEdge(c.FlowGraph, graphNode, caller)
				for x := range caller.Out() {
					que = addNext(c, que, seen, elt, x, elt.Trace.Parent, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil && checkClosureReturns(graphNode, elt.ClosureTrace.Label) {
				addEdge(c.FlowGraph, graphNode, elt.ClosureTrace.Label)
				for cCall := range elt.ClosureTrace.Label.Out() {
					que = addNext(c, que, seen, elt, cCall, elt.Trace, elt.ClosureTrace.Parent)
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					addEdge(c.FlowGraph, graphNode, callSite)
					for x := range callSite.Out() {
						que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "Return node %s does not return anywhere.\n", elt.Node.String())
				fmt.Fprintf(os.Stderr, "In %s\n", elt.Node.Position(c))
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *CallNode:
			// checkNoGoRoutine(c, goroutines, graphNode)

			// We pop the call from the stack and continue inside the caller
			var trace *NodeTree[*CallNode]
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, trace, elt.ClosureTrace)
			}

		// Tainting a bound variable node means that the free variable in a closure will be tainted.
		// For example:
		// 1:  x := "ok" // x is not tainted here
		// 2: f := func(s string) string { return s + x } // x is bound here
		// 3: x := source()
		// 4: sink(f("ok")) // will raise an alarm
		// The flow goes from x at line 3, to x being bound at line 2, to x the free variable
		// inside the closure definition, and finally from the return of the closure to the
		// call site of the closure inside a sink.
		// For more examples with closures, see testdata/src/taint/cross-function/closures/main.go
		case *BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the dataflow edges between arguments
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

			closureNode := graphNode.ParentNode()

			if closureNode.ClosureSummary == nil {
				printMissingClosureSummaryMessage(c, closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				c.AddError(fmt.Errorf("no free variable matching bound variable at position %d in %s",
					graphNode.Index(), closureNode.ClosureSummary.Parent.String()))
			}

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		case *FreeVarNode:
			// Flows inside the function
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

			// TODO: back flows when the free variables are tainted by the closure's body

		// A closure node can be reached if a function value is tainted
		// TODO: add an example
		case *ClosureNode:
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the dataflow
		// graph summaries.
		case *SyntheticNode:
			for x := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace)
			}
		case *AccessGlobalNode:
			graphNode.Global.mutex.Lock()
			global := graphNode.Global
			if accesses, ok := c.FlowGraph.Globals[global]; !ok {
				if c.FlowGraph.Globals == nil {
					c.FlowGraph.Globals = make(map[*GlobalNode]map[*AccessGlobalNode]bool)
				}
				c.FlowGraph.Globals[global] = map[*AccessGlobalNode]bool{graphNode: true}
			} else {
				if accesses == nil {
					accesses = make(map[*AccessGlobalNode]bool)
				}
				accesses[graphNode] = true
			}
			graphNode.Global.mutex.Unlock()

			if graphNode.IsWrite {
				// Tainted data is written to ALL locations where the global is read.
				for x := range graphNode.Global.ReadLocations {
					// Global jump makes trace irrelevant if we don't follow the call graph!
					que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
				}
			} else {
				// From a read location, tainted data follows the out edges of the node
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}
		}
	}
}

// addEdge adds forward edge src -> dst and backwards edge src <- dst to graph.
func addEdge(graph *CrossFunctionFlowGraph, src GraphNode, dst GraphNode) {
	if _, ok := graph.ForwardEdges[src]; !ok {
		graph.ForwardEdges[src] = make(map[GraphNode]bool)
	}
	graph.ForwardEdges[src][dst] = true

	if _, ok := graph.BackwardEdges[dst]; !ok {
		graph.BackwardEdges[dst] = make(map[GraphNode]bool)
	}
	graph.BackwardEdges[dst][src] = true
}

// findCalleeSummary returns the summary graph of callee in summaries if present. Returns nil if not.
func findCalleeSummary(callee *ssa.Function, summaries map[*ssa.Function]*SummaryGraph) *SummaryGraph {
	if summary, ok := summaries[callee]; ok {
		return summary
	}

	for summarized, summary := range summaries {
		// sometimes a "thunk" function will be the same as a normal function,
		// just with a different name ending in $thunk and the same position
		if (strings.HasPrefix(callee.String(), summarized.String()) ||
			strings.HasPrefix(summarized.String(), callee.String())) &&
			callee.Pos() == summarized.Pos() {
			return summary
		}
	}

	return nil
}

// findClosureSummary returns the summary graph of the function used in the MakeClosure instruction instr
func findClosureSummary(instr *ssa.MakeClosure, summaries map[*ssa.Function]*SummaryGraph) *SummaryGraph {
	switch funcValue := instr.Fn.(type) {
	case *ssa.Function:
		if summary, ok := summaries[funcValue]; ok {
			return summary
		} else {
			return nil
		}
	default:
		return nil
	}
}

// IsSourceFunction returns true if cfg identifies f as a source.
func IsSourceFunction(cfg *config.Config, f *ssa.Function) bool {
	pkg := packagescan.PackageNameFromFunction(f)
	return cfg.IsSource(config.CodeIdentifier{Package: pkg, Method: f.Name()})
}

func summaryNotFound(g *CrossFunctionFlowGraph, node *CallNode) {
	if g.cache.Config.Verbose {
		g.cache.Logger.Printf("Could not find summary of %s", node.callSite.String())
	}
}

// openCoverage opens the coverage file, if the config requires it.
// the caller is responsible for closing the file if non-nil
func openCoverage(c *Cache) *os.File {
	var err error
	var coverage *os.File

	if c.Config.ReportCoverage {
		coverage, err = os.CreateTemp(c.Config.ReportsDir, "coverage-*.out")
		if err != nil {
			coverage = nil
			c.Logger.Printf("Warning: could not create coverage file, continuing.\n")
			c.Logger.Printf("Error was: %s", err)
		} else {
			c.Logger.Printf("Writing coverage information in %s.\n", coverage.Name())
			_, _ = coverage.WriteString("mode: set\n")
		}
	}
	return coverage
}

// openSummaries returns a non-nil opened file if the configuration is set properly
// the caller is responsible for closing the file if non-nil
func openSummaries(c *Cache) *os.File {
	var err error
	var summariesFile *os.File

	if c.Config.ReportSummaries {
		summariesFile, err = os.CreateTemp(c.Config.ReportsDir, "summaries-*.out")
		if err != nil {
			summariesFile = nil
			c.Logger.Printf("Warning: could not create summaries files, continuing.\n")
			c.Logger.Printf("Error was: %s", err)
		} else {
			c.Logger.Printf("Writing summaries in %s.\n", summariesFile.Name())
		}
	}
	return summariesFile
}

// UnwindCallstackFromCallee returns the CallNode that should be returned upon. It satisfies the following conditions:
// - the CallNode is in the callsites set
// - the CallNode is in the trace
// If no CallNode satisfies these conditions, nil is returned.
func UnwindCallstackFromCallee(callsites map[ssa.CallInstruction]*CallNode, trace *NodeTree[*CallNode]) *CallNode {
	// no trace = nowhere to return to.
	if trace == nil {
		return nil
	}

	// the number of callsites in a call is expected to be small
	for _, x := range callsites {
		if x.CallSite() == trace.Label.CallSite() && x.Callee() == trace.Label.Callee() {
			return x
		}
	}
	// no return node has been found
	return nil
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *Cache,
	que []*VisitorNode,
	seen map[NodeWithTrace]bool,
	cur *VisitorNode,
	node GraphNode,
	trace *NodeTree[*CallNode],
	closureTrace *NodeTree[*ClosureNode]) []*VisitorNode {

	newNode := NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode] || trace.IsLasso() || cur.Depth > c.Config.MaxDepth {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *ReturnNode:
		pStack = pStack.Parent()
	case *ParamNode:
		pStack = pStack.Add(curNode)
	}

	newVis := &VisitorNode{
		NodeWithTrace: newNode,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}

// checkIndex checks that the indexed graph node is valid in the parent node call site
func checkIndex(c *Cache, node IndexedGraphNode, callSite *CallNode, msg string) error {
	if node.Index() >= len(callSite.Args()) {
		pos := c.Program.Fset.Position(callSite.CallSite().Value().Pos())
		c.Logger.Printf("%s: trying to access index %d of %s, which has"+
			" only %d elements\nSee: %s\n", msg, node.Index(), callSite.String(), len(callSite.Args()),
			pos)
		return fmt.Errorf("bad index %d at %s", node.Index(), pos)
	}
	return nil
}

func checkClosureReturns(returnNode *ReturnNode, closureNode *ClosureNode) bool {
	if returnNode.Graph() == closureNode.ClosureSummary {
		return true
	}
	return false
}
