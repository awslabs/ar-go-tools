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

package check

import (
	"go/token"
	"slices"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/lang"
)

// findUnsoundFeatures returns the unsound features in all functions reachable from function f
// according to callgraph cg.
// For efficiency, it only returns the first 5 unsound features.
func findUnsoundFeatures(cg *callgraph.Graph, f *ssa.Function) UnsoundCheckFeatures {
	queue := []*callgraph.Node{cg.Nodes[f]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})
	var unsafes []token.Position
	var gos []token.Position
	var globals []token.Position

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if _, ok := seen[node]; ok || node.Func == nil {
			continue
		}
		seen[node] = struct{}{}

		// A function may be visited multiple times in different calling contexts so only analyze
		// each function once.
		if _, ok := seenFunc[node.Func]; ok {
			continue
		}
		seenFunc[node.Func] = struct{}{}

		lang.IterateInstructions(node.Func, func(_ int, instr ssa.Instruction) {
			prog := instr.Parent().Prog
			var operands []*ssa.Value
			operands = instr.Operands(operands)
			for _, operand := range operands {
				if _, ok := (*operand).(*ssa.Global); ok {
					pos := prog.Fset.Position(instr.Pos())
					if !slices.Contains(globals, pos) {
						globals = append(globals, pos)
					}
				}
			}

			if isUnsafeInstr(instr) {
				pos := prog.Fset.Position(instr.Pos())
				// This is fast because len(unsafes) is never greater than 5 or so.
				if !slices.Contains(unsafes, pos) {
					unsafes = append(unsafes, pos)
				}
			}
			if isGoroutineInstr(instr) {
				pos := prog.Fset.Position(instr.Pos())
				if !slices.Contains(gos, pos) {
					gos = append(gos, pos)
				}
			}
		})

		if len(unsafes)+len(gos) >= 5 {
			return UnsoundCheckFeatures{UnsafeUsages: unsafes, GoUsages: gos}
		}

		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
	}

	return UnsoundCheckFeatures{UnsafeUsages: unsafes, GoUsages: gos, GlobalUsages: globals}
}

// isGoroutineInstr returns true if instr is a goroutine call.
func isGoroutineInstr(instr ssa.Instruction) bool {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return false
	}

	_, ok = call.(*ssa.Go)
	return ok
}

// isUnsafeInstr returns true if instr uses the unsafe package.
//
// TODO This is taken from analysis/dataflow/report.go and should eventually be refactored into a
// common package.
func isUnsafeInstr(instr ssa.Instruction) bool {
	switch instr := instr.(type) {
	case ssa.CallInstruction:
		call := instr.Common()
		if call == nil {
			return false
		}

		switch val := call.Value.(type) {
		case *ssa.Function:
			pkg := lang.PkgPathFromFunction(val)
			// Call a function from an unsafe package.
			if strings.HasPrefix(pkg, "unsafe") {
				return true
			}
		case *ssa.Builtin:
			// Call an unsafe builtin function.
			if _, ok := unsafeBuiltins[val.Name()]; ok {
				return true
			}
		}
	case *ssa.Alloc:
		typ := instr.Type().Underlying()
		if typ == nil {
			return false
		}
		pkg := lang.GetPackageOfType(typ)
		if pkg == nil {
			return false
		}
		// Allocate an object of an unsafe type.
		if strings.HasPrefix(pkg.Name(), "unsafe") {
			return true
		}
	case *ssa.Convert:
		typ := instr.Type()
		if typ == nil {
			return false
		}
		// Convert data to an unsafe pointer.
		if strings.Contains(typ.String(), "unsafe") {
			return true
		}
	}

	return false
}

// unsafeBuiltins are the builtins that are from the unsafe package.
var unsafeBuiltins = map[string]struct{}{
	"Alignof":     {},
	"Offsetof":    {},
	"Sizeof":      {},
	"Pointer":     {},
	"SliceData":   {},
	"String":      {},
	"StringData":  {},
	"Slice":       {},
	"Add":         {},
	"IntegerType": {},
}
