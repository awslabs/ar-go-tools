// Package dataflow contains abstractions for reasoning about data flow within programs.
package dataflow

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

// CrossFunctionFlowGraph represents a cross-function data flow graph.
type CrossFunctionFlowGraph struct {
	Summaries map[*ssa.Function]*SummaryGraph
	cache     *Cache
	built     bool
}

// NewCrossFunctionFlowGraph returns a new non-built cross function flow graph
func NewCrossFunctionFlowGraph(summaries map[*ssa.Function]*SummaryGraph, cache *Cache) CrossFunctionFlowGraph {
	return CrossFunctionFlowGraph{Summaries: summaries, cache: cache, built: false}
}

func (g *CrossFunctionFlowGraph) IsBuilt() bool {
	return g.built
}

// Print prints each of the function summaries in the graph.
func (g *CrossFunctionFlowGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	for _, summary := range g.Summaries {
		summary.Print(w)
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

// SourceVisitor represents a visitor that runs the inter-procedural analysis from a specific source and adds any
// detected data flow to dataFlows.
type SourceVisitor func(logger *log.Logger, c *Cache, source NodeWithTrace, dataFlows DataFlows, coverageFile io.StringWriter)

// BuildGraph builds the cross function flow graph by connecting summaries together
func (g *CrossFunctionFlowGraph) BuildGraph() {
	c := g.cache
	logger := c.Logger
	// Open a file to output summaries
	summariesFile := openSummaries(c)
	if summariesFile != nil {
		defer summariesFile.Close()
	}

	// Build the cross-function data flow graph: link all the summaries together, identify source nodes
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
		}
		if summariesFile != nil {
			_, _ = summariesFile.WriteString(fmt.Sprintf("%s:\n", summary.Parent.String()))
			summary.Print(summariesFile)
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

func (g *CrossFunctionFlowGraph) RunCrossFunctionPass(dataFlows DataFlows, visitor SourceVisitor, coverage *os.File) {
	var sourceFuncs []*SummaryGraph
	var entryPoints []NodeWithTrace

	for _, summary := range g.Summaries {
		// Identify the entry points for that function: all the call sites if it is a source, and all the synthetic
		// nodes that are sources in the function body.
		for _, snode := range summary.SyntheticNodes {
			entry := NodeWithTrace{Node: snode, Trace: nil}
			entryPoints = append(entryPoints, entry)
		}
		if isSourceFunction(g.cache.Config, summary.Parent) {
			sourceFuncs = append(sourceFuncs, summary)
		}
	}

	for _, summary := range sourceFuncs {
		for _, node := range summary.Callsites {
			entry := NodeWithTrace{node, nil, nil}
			entryPoints = append(entryPoints, entry)
		}
	}

	g.cache.Logger.Printf("--- # sources of tainted data: %d ---\n", len(entryPoints))

	// Run the analysis for every source point. We may be able to change this to run the analysis for all sources
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitor(g.cache.Logger, g.cache, entry, dataFlows, coverage)
	}
}

// CrossFunctionPass runs the inter-procedural pass on the inter-procedural flow graph. Candidate data flows, in the
// form of a map from sink to sources, will be added to dataFlows. Most of the logic is in visitor that is called for
// each possible source node identified.
//
// This function does nothing if there are no summaries (i.e. `len(g.summaries) == 0` or if `cfg.SkipInterprocedural`
// is set to true.
func (g *CrossFunctionFlowGraph) CrossFunctionPass(c *Cache, dataFlows DataFlows, visitor SourceVisitor) {
	// Skip the pass if user configuration demands it
	if c.Config.SkipInterprocedural || len(g.Summaries) == 0 {
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
	g.RunCrossFunctionPass(dataFlows, visitor, coverage)
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

func isSourceFunction(cfg *config.Config, f *ssa.Function) bool {
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

// CheckCallStackContainsCallsite returns true if nodes contains a call node with the same callsite as the node
func CheckCallStackContainsCallsite(c *Cache, nodes map[ssa.CallInstruction]*CallNode, node *CallNode) bool {
	// The number of nodes in a call is expected to be small
	for _, x := range nodes {
		if x.CallSite() == node.CallSite() && x.Callee() == node.Callee() {
			return true
		}
	}
	return false
}
