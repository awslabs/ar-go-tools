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

// Package argalias implements an analysis that proves that no arguments to a
// specified function may alias each other's memory.
package argalias

import (
	"errors"
	"fmt"
	"go/token"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/modptr"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	goPointer "golang.org/x/tools/go/pointer"
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

// Result represents the result of the analysis for a single entrypoint.
type Result struct {
	Entrypoint Entrypoint
	// ArgsAliased is a mapping from an entrypoint argument value to the values
	// of the entrypoint arguments it aliases.
	ArgsAliased map[ssa.Value][]ssa.Value
}

// Analyze runs the analysis on lp.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result, goPtrRes *goPointer.Result) ([]Result, error) {
	var results []Result
	prog := lp.Program
	log := config.NewLogGroup(cfg)

	reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)
	var errs []error
	ac := &modptr.AliasCache{
		GoPtrRes:       goPtrRes,
		PtrRes:         ptrRes,
		Prog:           prog,
		ReachableFuncs: reachable,
		ObjectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}),
	}
	// HACK reuse the existing modval specs to get the entrypoints
	for _, spec := range cfg.ModificationTrackingProblems {
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
func analyze(log *config.LogGroup, ac *modptr.AliasCache, spec config.ModValSpec) ([]Result, error) {
	var errs []error
	entrypoints := findEntrypoints(ac, spec)
	if len(entrypoints) == 0 {
		return nil, fmt.Errorf("no entrypoints found")
	}

	var res []Result
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
			res = append(res, Result{
				Entrypoint:  entry,
				ArgsAliased: argsAliased,
			})
		}
	}

	return res, errors.Join(errs...)
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func findEntrypoints(ac *modptr.AliasCache, spec config.ModValSpec) []Entrypoint {
	var entrypoints []Entrypoint
	for fn, node := range ac.GoPtrRes.CallGraph.Nodes {
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

func findEntrypoint(ac *modptr.AliasCache, spec config.ModValSpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.GoPtrRes, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.Prog.Fset.Position(call.Pos())
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
