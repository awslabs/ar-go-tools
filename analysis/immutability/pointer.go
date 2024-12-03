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

package immutability

import (
	"fmt"
	"strconv"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// AliasCache represents a "global" cache for transitive pointers and aliases.
//
// The analysis only searches for pointers and aliases that are reachable from a
// single entrypoint, but this cache helps if there are multiple entrypoints
// that need alias information computed from previous entrypoints.
type AliasCache struct {
	State          *ptr.State
	ReachableFuncs map[*ssa.Function]bool
	ObjectPointees map[ssa.Value]map[*pointer.Object]struct{}
}

// Objects returns all the unique Objects that val points to.
func (ac *AliasCache) Objects(val ssa.Value) map[*pointer.Object]struct{} {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// if val is an interface, the object is the concrete struct
		val = mi.X
	}
	if res, ok := ac.ObjectPointees[val]; ok && len(res) > 0 {
		return res
	}

	ptrs := FindAllPointers(ac.State.PointerAnalysis, val)
	if len(ptrs) == 0 {
		return nil
	}

	res := make(map[*pointer.Object]struct{}, len(ptrs))
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}
			res[obj] = struct{}{}
		}
	}

	ac.ObjectPointees[val] = res
	return res
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func (ac *AliasCache) findEntrypoints(spec config.ImmutabilitySpec) map[Entrypoint]struct{} {
	entrypoints := make(map[Entrypoint]struct{})
	for fn, node := range ac.State.PointerAnalysis.CallGraph.Nodes {
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

			entry, ok := ac.findEntrypoint(spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints[entry] = struct{}{}
		}
	}

	return entrypoints
}

func (ac *AliasCache) findEntrypoint(spec config.ImmutabilitySpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.State.PointerAnalysis, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.State.Program.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		// TODO parse context beforehand to prevent panics
		idx, err := strconv.Atoi(cid.Context)
		if err != nil {
			err := fmt.Errorf("cid context is not a valid argument index: %v", err)
			panic(err)
		}
		if idx < 0 {
			err := fmt.Errorf("cid context is not a valid argument index: %v < 0", idx)
			panic(err)
		}

		args := lang.GetArgs(call)
		if len(args) < idx {
			fmt.Printf("arg index: %v < want %v\n", len(args), idx)
			return Entrypoint{}, false
		}

		val := args[idx]
		if cid.Type != "" && !cid.MatchType(val.Type()) {
			continue
		}

		return Entrypoint{Val: val, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

// FindAllPointers returns all the pointers that point to v.
//
// Copied from analysis/lang package.
func FindAllPointers(res *pointer.Result, v ssa.Value) []pointer.Pointer {
	var allptr []pointer.Pointer
	if ptr, ptrExists := res.Queries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	// By indirect query
	if ptr, ptrExists := res.IndirectQueries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	return allptr
}
