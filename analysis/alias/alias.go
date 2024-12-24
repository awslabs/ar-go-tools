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

// Package alias implements a must-not-alias analysis.
// The analysis only works on function call arguments for now.
package alias

import (
	"errors"
	"fmt"
	"go/token"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/ssa"
)

// Entrypoint represents an Entrypoint to the analysis.
// This is the arguments to a function call specified by the configuration file's
// modval analysis spec.
type Entrypoint struct {
	// Args are the argument's values (ordered).
	Args []ssa.Value
	// Call is the call instruction containing the arguments.
	Call ssa.CallInstruction
	// Pos is the position of the callsite, not the argument values themselves.
	Pos token.Position
}

// AnalysisResult represents the result of the analysis for a single entrypoint.
type AnalysisResult struct {
	Entrypoint Entrypoint
	// ArgsAliased is a mapping from an entrypoint argument value to the values
	// of the entrypoint arguments it aliases.
	ArgsAliased map[ssa.Value][]ssa.Value
}

// Analyze runs the analysis on state.
func Analyze(state *ptr.State) ([]AnalysisResult, error) {
	var results []AnalysisResult
	cfg := state.Config
	log := config.NewLogGroup(cfg)

	var errs []error
	ac := ptr.NewAliasCache(state)
	// HACK reuse the existing immutability specs to get the entrypoints
	for _, spec := range cfg.ImmutabilityProblems {
		res, err := analyze(log, ac, spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %v: %v", spec, err))
			continue
		}

		results = append(results, res...)
	}

	return results, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and returns a list of results
// with the aliased arguments.
func analyze(log *config.LogGroup, ac *ptr.AliasCache, spec config.ImmutabilitySpec) ([]AnalysisResult, error) {
	var errs []error
	entrypoints := findEntrypoints(ac, spec)
	if len(entrypoints) == 0 {
		return nil, fmt.Errorf("no entrypoints found")
	}

	var res []AnalysisResult
	type argMem struct {
		arg     ssa.Value
		nodeset *intsets.Sparse
	}
	for _, entry := range entrypoints {
		log.Infof("ENTRY: %v in %v at %v\n", entry.Call, entry.Call.Parent(), entry.Pos)

		var ams []argMem
		for _, arg := range entry.Args {
			// only find aliases to args that are pointer types
			if !pointer.CanPoint(arg.Type()) {
				continue
			}

			log.Infof("\targ: %v (type: %v)\n", arg.Name(), arg.Type())
			objs := ac.Objects(arg)
			nodeset := &intsets.Sparse{}
			for obj := range objs {
				for _, nid := range obj.NodeIDs() {
					nodeset.Insert(int(nid))
				}
			}
			argMem := argMem{arg: arg, nodeset: nodeset}
			ams = append(ams, argMem)
		}

		argsAliased := make(map[ssa.Value][]ssa.Value)
		for i, am := range ams {
			for j := i + 1; j < len(ams); j++ {
				if am.nodeset.Intersects(ams[j].nodeset) {
					arg := entry.Args[i]
					argsAliased[arg] = append(argsAliased[arg], entry.Args[j])
				}
			}
		}

		if len(argsAliased) > 0 {
			res = append(res, AnalysisResult{
				Entrypoint:  entry,
				ArgsAliased: argsAliased,
			})
		}
	}

	return res, errors.Join(errs...)
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func findEntrypoints(ac *ptr.AliasCache, spec config.ImmutabilitySpec) []Entrypoint {
	var entrypoints []Entrypoint
	for fn, node := range ac.PtrState.PointerAnalysis.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		if _, ok := ac.ReachableFuncs[fn]; !ok {
			continue
		}

		for _, inEdge := range node.In {
			if inEdge == nil || inEdge.Site == nil {
				continue
			}

			entry, ok := findEntrypoint(ac, spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints = append(entrypoints, entry)
		}
	}

	return entrypoints
}

func findEntrypoint(ac *ptr.AliasCache, spec config.ImmutabilitySpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.PtrState.PointerAnalysis, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.PtrState.Program.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		args := lang.GetArgs(call)
		val := args[0]
		if cid.Type != "" && !cid.MatchType(val.Type()) {
			continue
		}

		return Entrypoint{Args: args, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

// ReportResults writes results to a string and returns true if the analysis should fail.
func ReportResults(results []AnalysisResult) (string, bool) {
	failed := false

	w := &strings.Builder{}
	w.WriteString("\nalias analysis results:\n")
	w.WriteString("-----------------------------\n")
	// Prints location of aliases in the SSA
	for _, result := range results {
		entry := result.Entrypoint
		entryPos := entry.Pos
		for entryArg, aliasedArgs := range result.ArgsAliased {
			w.WriteString(fmt.Sprintf(
				"potential aliases of arg %s of call %s in %s: at %s\n",
				entryArg,
				entry.Call.String(),
				entryArg.Parent().String(),
				entryPos.String())) // safe %s (position string)
			for _, alias := range aliasedArgs {
				w.WriteString(fmt.Sprintf("\tmay be aliased by arg %s\n", alias))
				failed = true
			}
		}
	}

	return w.String(), failed
}
