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

package dataflow

import (
	"fmt"
	"go/types"
	"strconv"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// BindingInfo contains information about a closure creation location (the MakeClosure instruction) and an index for
// the bound variable / free variable that the binding info references.
type BindingInfo struct {
	// MakeClosure is the instruction where the closure has been created
	MakeClosure *ssa.MakeClosure

	// BoundIndex is the index of the bound variables. It should satisfy 0 <= BoundIndex <= len(MakeClosure.Bindings)
	BoundIndex int
}

func (b BindingInfo) String() string {
	if b.MakeClosure == nil {
		return "nil"
	}
	return b.MakeClosure.String() + "@" + strconv.Itoa(b.BoundIndex)
}

// Type returns the types.Type of the binding
func (b BindingInfo) Type() types.Type {
	if b.MakeClosure == nil || b.BoundIndex < 0 || b.BoundIndex >= len(b.MakeClosure.Bindings) {
		return nil
	}
	bv := b.MakeClosure.Bindings[b.BoundIndex]
	if bv == nil {
		return nil
	}
	return bv.Type()
}

// BoundingMap maps values to the binding infos that reference the closures that captured the value.
// In other words, for a value v and BoundingMap X, if X[v] is non-empty, then v is captured by some closure. For each
// y in X[v], y.MakeClosure is the instruction that captures it and y.BoundIndex is the bound variable that aliases v.
type BoundingMap map[ssa.Value]map[*BindingInfo]bool

// RunBoundingAnalysis computes the BoundingMap of the program in the analyzer state by iterating over the instructions
// of each reachable function.
func RunBoundingAnalysis(state *State) (BoundingMap, error) {
	if state.PointerAnalysis == nil {
		return nil, fmt.Errorf("pointer analysis should run before bounding analysis")
	}
	bindMap := map[ssa.Value]map[*BindingInfo]bool{}
	for function := range state.ReachableFunctions() {
		lang.IterateInstructions(function, func(_ int, instr ssa.Instruction) {
			InspectInstruction(state, bindMap, instr)
		})
	}
	return bindMap, nil
}

// InspectInstruction adds information to the bindMap if instruction is a closure and the pointer analysis
// contains information about where the bound variables are allocated.
func InspectInstruction(state *State, bindMap BoundingMap, instruction ssa.Instruction) {
	makeClosure, ok := instruction.(*ssa.MakeClosure)
	if !ok {
		return
	}
	for i, b := range makeClosure.Bindings {
		if ptr, ok := state.PointerAnalysis.Queries[b]; ok {
			registerBinding(makeClosure, i, ptr, bindMap)
		}
		if ptr, ok := state.PointerAnalysis.IndirectQueries[b]; ok {
			registerBinding(makeClosure, i, ptr, bindMap)
		}
	}
}

// registerBinding adds the bound variable at index i of the makeClosure instruction to the bindMap for each label
// in the pointer ptr
func registerBinding(makeClosure *ssa.MakeClosure, i int, ptr pointer.Pointer, bindMap BoundingMap) {
	for _, label := range ptr.PointsTo().Labels() {
		if label.Value() != nil {
			// We are using values to identify uniquely allocation sites. It seems labels are not unique for that
			// purpose. Since we are mostly interested in data flow through values, tracking only values is
			// sufficient.
			info := &BindingInfo{
				MakeClosure: makeClosure,
				BoundIndex:  i,
			}
			if _, ok := bindMap[label.Value()]; !ok {
				bindMap[label.Value()] = map[*BindingInfo]bool{info: true}
			} else {
				bindMap[label.Value()][info] = true
			}
		}
	}
}
