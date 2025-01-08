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

// Package goroutine implements the front-end for the goroutine analysis.
package goroutine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Usage is the CLI help message.
const Usage = `Perform goroutine analysis on your packages.
Usage:
    argot goroutine [options] <package path(s)>
Examples:
# argot goroutine -config config.yaml package...
`

// Run runs the goroutine analysis.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	logger := config.NewLogGroup(cfg)
	logger.Infof(formatutil.Faint("Argot goroutine tool - " + analysis.Version))

	// Override config parameters with command-line parameters
	if flags.Verbose {
		logger.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		logger = config.NewLogGroup(cfg)
	}

	failCount := 0
	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Tool:        config.GoroutineTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get goroutine targets: %s", err)
	}
	for targetName, targetFiles := range actualTargets {
		if err := runTarget(cfg, targetName, targetFiles, flags); err != nil {
			logger.Errorf("Analysis for %s failed: %s", targetName, err)
			failCount += 1
		}
	}

	if failCount > 0 {
		os.Exit(1)
	}

	return nil
}

func runTarget(
	cfg *config.Config,
	targetName string,
	targetFiles []string,
	flags tools.CommonFlags,
) error {
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	start := time.Now()

	c := config.NewState(cfg, targetName, targetFiles, loadOptions)
	state, err := result.Bind(result.Bind(loadprogram.NewState(c), ptr.NewState), dataflow.NewState).Value()
	if err != nil {
		return fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	// TODO support checking parameters other than the first
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid config: %v", err)
	}

	criticalFuncs := []*ssa.Function{}
	for f := range state.PointerAnalysis.CallGraph.Nodes {
		if isCriticalFunc(cfg, f) {
			criticalFuncs = append(criticalFuncs, f)
		}
	}

	logger := state.Logger
	logger.Debugf("Found %d functions to check\n", len(criticalFuncs))
	reachable, roots := markReachableTo(criticalFuncs, state.PointerAnalysis.CallGraph)
	logger.Debugf("Found %d functions that may reach checked functions\n", len(reachable))

	logger.Infof(formatutil.Faint("Beginning bottom-up phase") + "\n")
	if err := escape.InitializeEscapeAnalysisState(state); err != nil {
		logger.Errorf("Analysis failed: %v\n", err)
		os.Exit(1)
	}

	logger.Infof(formatutil.Faint("Beginning top-down phase") + "\n")
	visitNodes := topDown(state, state.EscapeAnalysisState, roots, reachable)
	success := topDownPhase(logger, cfg, visitNodes, state.EscapeAnalysisState)

	duration := time.Since(start)
	state.Logger.Infof("")
	state.Logger.Infof(strings.Repeat("*", 80))
	state.Logger.Infof("Analysis took %3.4f s", duration.Seconds())
	state.Logger.Infof("")

	if !success {
		return fmt.Errorf("goroutine analysis found problems, inspect logs for more information")
	}

	return nil
}

func topDownPhase(logger *config.LogGroup, cfg *config.Config, visitNodes []*callgraphVisitNode, st dataflow.EscapeAnalysisState) bool {
	success := true
	// mainFunc := findFunction(lp.Program, "main")
	for _, node := range visitNodes {
		if isCriticalFunc(cfg, node.fun) {
			for i, reason := range st.ParameterPostEscape(node.context) {
				logger.Debugf("Checking that parameter %d of %v called in %v does not escape thread in post-state\n", i, node.fun, node.parent.fun)
				if reason != nil {
					logger.Errorf("\tParameter %s of %v has escaped: %v\n", node.fun.Params[i].Name(), node.fun, reason)
					success = false
					n := node
					for n != nil {
						logger.Debugf("at: %v\n", n.fun)
						n = n.parent
					}
				}
			}
			// run the function summary and then check if the parameters are still local

		}
	}

	return success
}

func isCriticalFunc(cfg *config.Config, f *ssa.Function) bool {
	for _, mv := range cfg.ImmutabilityProblems {
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

func topDown(state *dataflow.State, escapeState dataflow.EscapeAnalysisState, roots map[*ssa.Function]struct{}, reachable map[*ssa.Function]struct{}) []*callgraphVisitNode {

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
		state.Logger.Debugf("%sAnalyzing %v\n", strings.Repeat("  ", depth), f)
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

func validateConfig(cfg *config.Config) error {
	for _, spec := range cfg.ImmutabilityProblems {
		for _, val := range spec.Values {
			if val.Context != "0" {
				return fmt.Errorf("invalid context for value: %v (want %v, got %v)", val, "0", val.Context)
			}
		}
	}

	return nil
}
