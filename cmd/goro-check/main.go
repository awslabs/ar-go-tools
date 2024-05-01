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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

var (
	// Flags
	configPath = flag.String("config", "", "Config file path for analysis")
	verbose    = flag.Bool("verbose", false, "Verbose printing on standard output")
	maxDepth   = flag.Int("max-depth", -1, "Override max depth in config")
	// Other constants
	buildmode = ssa.InstantiateGenerics // necessary for reachability
	version   = "unknown"
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

const usage = ` Perform goroutine analysis on your packages.
Usage:
    goro-check [options] <package path(s)>
Examples:
# goro-check -config config.yaml package...
`

func main() {
	var err error
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "", log.Flags())

	cfg := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		cfg, err = config.LoadGlobal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %q\n", *configPath)
			os.Exit(1)
		}
	}

	// Override config parameters with command-line parameters
	if *verbose {
		cfg.LogLevel = int(config.DebugLevel)
	}
	if *maxDepth > 0 {
		cfg.MaxDepth = *maxDepth
	}

	logger.Printf(formatutil.Faint("Argot goro-check tool - build " + version))
	logger.Printf(formatutil.Faint("Reading sources") + "\n")

	lp, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()

	prog := lp.Program
	state, err := dataflow.NewInitializedAnalyzerState(config.NewLogGroup(cfg), cfg, prog)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization failed: %v\n", err)
		os.Exit(1)
	}

	criticalFuncs := []*ssa.Function{}
	for f := range state.PointerAnalysis.CallGraph.Nodes {
		if isCriticalFunc(cfg, f) {
			criticalFuncs = append(criticalFuncs, f)
		}
	}

	fmt.Printf("Found %d functions to check\n", len(criticalFuncs))
	reachable, roots := markReachableTo(criticalFuncs, state.PointerAnalysis.CallGraph)
	fmt.Printf("Found %d functions that may reach checked functions\n", len(reachable))

	logger.Printf(formatutil.Faint("Beginning bottom-up phase") + "\n")
	err = escape.InitializeEscapeAnalysisState(state)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	logger.Printf(formatutil.Faint("Beginning top-down phase") + "\n")
	visitNodes := topDown(state, state.EscapeAnalysisState, roots, reachable)
	success := topDownPhase(cfg, visitNodes)

	duration := time.Since(start)
	state.Logger.Infof("")
	state.Logger.Infof(strings.Repeat("*", 80))
	state.Logger.Infof("Analysis took %3.4f s", duration.Seconds())
	state.Logger.Infof("")

	if !success {
		os.Exit(1)
	}

	// Report(program, result)
}

func topDownPhase(cfg *config.Config, visitNodes []*callgraphVisitNode) bool {
	success := true
	// mainFunc := findFunction(lp.Program, "main")
	for _, node := range visitNodes {
		if isCriticalFunc(cfg, node.fun) {
			fmt.Printf("Checking %v\n", node.fun)
			for i, reason := range node.context.ParameterEscape() {
				if reason != nil {
					fmt.Printf("[ERROR] Parameter %d of %v has escaped: %v\n", i, node.fun, reason)
					success = false
					n := node
					for n != nil {
						fmt.Printf("at: %v\n", n.fun)
						n = n.parent
					}
				}
			}
		}
	}

	return success
}

func isCriticalFunc(cfg *config.Config, f *ssa.Function) bool {
	for _, mv := range cfg.ModificationTrackingProblems {
		funcPackage := lang.PackageNameFromFunction(f)
		if mv.IsValue(config.CodeIdentifier{Package: funcPackage, Method: f.Name()}) {
			return true
		}
	}
	return false
}

type callgraphVisitNode struct {
	parent   *callgraphVisitNode
	context  dataflow.EscapeCallContext
	fun      *ssa.Function
	locality map[ssa.Instruction]*dataflow.EscapeRationale
	// we don't explicitly keep track of the children here.
}

func topDown(state *dataflow.AnalyzerState, escapeState dataflow.EscapeAnalysisState, roots map[*ssa.Function]struct{}, reachable map[*ssa.Function]struct{}) []*callgraphVisitNode {

	allNodes := make([]*callgraphVisitNode, 0)

	currentNode := map[*ssa.Function]*callgraphVisitNode{}
	var analyze func(f *ssa.Function, ctx dataflow.EscapeCallContext, parent *callgraphVisitNode, depth int)

	analyze = func(f *ssa.Function, ctx dataflow.EscapeCallContext, parent *callgraphVisitNode, depth int) {
		var node *callgraphVisitNode
		added := false
		if n, ok := currentNode[f]; !ok {
			// haven't visited this node with the current context
			node = &callgraphVisitNode{parent, ctx, f, make(map[ssa.Instruction]*dataflow.EscapeRationale)}
			currentNode[f] = node
			allNodes = append(allNodes, node)
			added = true
		} else {
			node = n
			changed, merged := node.context.Merge(ctx)
			if !changed {
				// an invocation of analyze further up the stack has already computed locality
				// with a more general context.
				return
			}
			node.context = merged
		}
		fmt.Printf("%sAnalyzing %v\n", strings.Repeat("  ", depth), f)
		locality, callsites := escapeState.ComputeInstructionLocalityAndCallsites(f, node.context)
		node.locality = locality
		for callsite, info := range callsites {
			callees, _ := state.ResolveCallee(callsite, true)
			for callee := range callees {
				_, fReachable := reachable[f]
				if escapeState.IsSummarized(callee) && fReachable {
					analyze(callee, info.Resolve(callee), node, depth+1)
				} else {
					// skip
				}
			}
		}
		if added {
			delete(currentNode, f)
		}
	}
	for root := range roots {
		rootContext := escapeState.ComputeArbitraryContext(root)
		analyze(root, rootContext, nil, 0)
		for f := range currentNode {
			delete(currentNode, f)
		}
	}
	return allNodes
}

func markReachableTo(funcs []*ssa.Function, callgraph *callgraph.Graph) (reachable map[*ssa.Function]struct{}, roots map[*ssa.Function]struct{}) {
	reachable = map[*ssa.Function]struct{}{}
	roots = map[*ssa.Function]struct{}{}
	for len(funcs) > 0 {
		f := funcs[len(funcs)-1]
		funcs = funcs[:len(funcs)-1]
		reachable[f] = struct{}{}
		if node, ok := callgraph.Nodes[f]; ok {
			if node.Func.String() == "command-line-arguments.init" || node.Func.String() == "command-line-arguments.main" {
				roots[f] = struct{}{}
			}
			for _, in := range node.In {
				if _, ok := in.Site.(*ssa.Go); ok {
					roots[f] = struct{}{}
					continue
				}
				if _, ok := reachable[in.Caller.Func]; !ok {
					funcs = append(funcs, in.Caller.Func)
					reachable[f] = struct{}{}
				}
			}
		}
	}
	return reachable, roots
}
