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
}

func NewCrossFunctionFlowGraph(summaries map[*ssa.Function]*SummaryGraph, cache *Cache) CrossFunctionFlowGraph {
	return CrossFunctionFlowGraph{Summaries: summaries, cache: cache}
}

// Print prints each of the function summaries in the graph.
func (g CrossFunctionFlowGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	for _, summary := range g.Summaries {
		summary.Print(w)
	}
	fmt.Fprintf(w, "}\n")
}

// Trace is a doubly-linked list with a pointer to origin where each node is a call site.
type Trace struct {
	Call   *CallNode
	Origin *Trace
	Parent *Trace
	Next   []*Trace
	len    int
}

func NewTrace(initNode *CallNode) *Trace {
	origin := &Trace{Call: initNode, Parent: nil, Next: []*Trace{}, len: 1}
	origin.Origin = origin
	return origin
}

func (n *Trace) String() string {
	if n == nil || n.len == 0 {
		return ""
	}
	s := make([]string, n.len)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.len >= 1 {
			s[cur.len-1] = cur.Call.FuncName()
		}
	}
	return strings.Join(s, "_")
}

// IsLasso checks returns true if the trace is more than one node long and the current node has the same call as the last node.
func (n *Trace) IsLasso() bool {
	if n == nil || n.len <= 1 {
		return false
	}
	last := n
	for cur := last.Parent; cur != nil; cur = cur.Parent {
		if cur.Call.FuncName() == last.Call.FuncName() {
			return true
		}
	}
	return false
}

func (n *Trace) Add(callNode *CallNode) *Trace {
	if n == nil {
		return NewTrace(callNode)
	} else {
		newNode := &Trace{Call: callNode, Parent: n, Next: []*Trace{}, Origin: n.Origin, len: n.len + 1}
		n.Next = append(n.Next, newNode)
		return newNode
	}

}

type NodeWithTrace struct {
	Node  GraphNode
	Trace *Trace
}

// SourceVisitor represents a visitor that runs the inter-procedural analysis from a specific source and adds any
// detected data flow to dataFlows.
type SourceVisitor func(logger *log.Logger, c *Cache, source NodeWithTrace, dataFlows DataFlows, coverageFile io.StringWriter)

// CrossFunctionPass runs the inter-procedural pass on the inter-procedural flow graph. Candidate data flows, in the
// form of a map from sink to sources, will be added to dataFlows. Most of the logic is in visitor that is called for
// each possible source node identified.
//
// This function does nothing if there are no summaries (i.e. `len(g.summaries) == 0` or if `cfg.SkipInterprocedural`
// is set to true.
func (g CrossFunctionFlowGraph) CrossFunctionPass(cfg *config.Config, logger *log.Logger, dataFlows DataFlows, visitor SourceVisitor) {
	var err error
	var sourceFuncs []*SummaryGraph
	var entryPoints []NodeWithTrace

	// Skip the pass if user configuration demands it
	if cfg.SkipInterprocedural || len(g.Summaries) == 0 {
		return
	}
	// Open the coverage file if specified in configuration
	var coverage *os.File
	if cfg.CoverageFile != "" {
		coverage, err = os.Create(cfg.CoverageFile)
		defer coverage.Close()
		if err != nil {
			coverage = nil
			logger.Printf("Warning: could not create coverage file %s, continuing.\n", cfg.CoverageFile)
			logger.Printf("Error was: %s", err)
		} else {
			_, _ = coverage.WriteString("mode: set\n")
		}
	}

	// Open a file to output summaries
	var summariesFile *os.File
	if cfg.OutputSummaries {
		summariesFile, err = os.Create("flow-summaries.out")
		defer summariesFile.Close()
		if err != nil {
			coverage = nil
			logger.Printf("Warning: could not create summaries files, continuing.\n")
			logger.Printf("Error was: %s", err)
		}
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
				if node.Callee() != nil {
					calleeSummary := findCalleeSummary(node.Callee(), g.Summaries)
					// If it's not in the generated summaries, try to fetch it from predefined summaries
					if calleeSummary == nil {
						calleeSummary = LoadPredefinedSummary(node.Callee(), g.cache.PointerAnalysis.CallGraph)
						if calleeSummary != nil {
							logger.Printf("Loaded %s from summaries.\n", node.Callee().String())
							g.Summaries[node.Callee()] = calleeSummary
						}
					}
					// Add edge from callee to caller (adding a call site in the callee)
					if calleeSummary != nil {
						calleeSummary.Callsites[node.CallSite()] = node
					}
					node.CalleeSummary = calleeSummary // nil is safe
				}
			}
		}

		// Identify the entry points for that function: all the call sites if it is a source, and all the synthetic
		// nodes that are sources in the function body.
		for _, snode := range summary.SyntheticNodes {
			entry := NodeWithTrace{Node: snode, Trace: nil}
			entryPoints = append(entryPoints, entry)
		}
		if isSourceFunction(cfg, summary.Parent) {
			sourceFuncs = append(sourceFuncs, summary)
		}
	}

	for _, summary := range sourceFuncs {
		for _, node := range summary.Callsites {
			entry := NodeWithTrace{node, nil}
			entryPoints = append(entryPoints, entry)
		}
	}

	logger.Printf("--- # sources of tainted data: %d ---\n", len(entryPoints))

	// Run the analysis for every source point. We may be able to change this to run the analysis for all sources
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitor(logger, g.cache, entry, dataFlows, coverage)
	}
}

// findCalleeSummary returns the summary graph of callee in summaries if present. Returns nil if not.
func findCalleeSummary(callee *ssa.Function, summaries map[*ssa.Function]*SummaryGraph) *SummaryGraph {
	if summary, ok := summaries[callee]; ok {
		return summary
	}

	for summarized, summary := range summaries {
		// sometimes a "thunk" function will be the same as a normal function,
		// just with a different name ending in $thunk and the same position
		if (strings.HasPrefix(callee.Name(), summarized.Name()) || strings.HasPrefix(summarized.Name(), callee.Name())) &&
			callee.Pos() == summarized.Pos() {
			return summary
		}
	}

	return nil
}

func isSourceFunction(cfg *config.Config, f *ssa.Function) bool {
	pkg := packagescan.PackageNameFromFunction(f)
	return cfg.IsSource(config.CodeIdentifier{Package: pkg, Method: f.Name()})
}
