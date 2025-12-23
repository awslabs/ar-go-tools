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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
)

// findUnsoundCheckFeatures returns the Go features used in all functions reachable from function f
// according to callgraph cg that make the check analysis unsound.
//
// For efficiency, it only returns the first 5 unsound features.
func findUnsoundCheckFeatures(
	cg *callgraph.Graph,
	f *ssa.Function,
	specs []dataflow.ScanningSpec,
) UnsoundCheckFeatures {
	queue := []*callgraph.Node{cg.Nodes[f]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})
	var globals []token.Position
	var unsafes []token.Position
	var reflects []token.Position
	var entrypoints []token.Position

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
			if isGlobalInstr(instr) {
				pos := prog.Fset.Position(instr.Pos())
				// This is fast because len(globals) is never greater than 5 or so.
				if !slices.Contains(globals, pos) {
					globals = append(globals, pos)
				}
			} else if isUnsafeOrReflect := isUnsafeOrReflectInstr(instr); isUnsafeOrReflect.isUnsafe {
				pos := prog.Fset.Position(instr.Pos())
				if !slices.Contains(unsafes, pos) {
					unsafes = append(unsafes, pos)
				}
			} else if isUnsafeOrReflect.isReflect {
				pos := prog.Fset.Position(instr.Pos())
				if !slices.Contains(unsafes, pos) {
					reflects = append(unsafes, pos)
				}
			} else if isEntrypoint(instr, specs) {
				pos := prog.Fset.Position(instr.Pos())
				if !slices.Contains(entrypoints, pos) {
					entrypoints = append(entrypoints, pos)
				}
			}
		})

		if len(globals)+len(unsafes)+len(reflects)+len(entrypoints) >= 5 {
			return UnsoundCheckFeatures{
				GlobalUsages:     globals,
				UnsafeUsages:     unsafes,
				ReflectUsages:    reflects,
				EntryPointUsages: entrypoints,
			}
		}

		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
	}

	return UnsoundCheckFeatures{
		GlobalUsages:     globals,
		UnsafeUsages:     unsafes,
		ReflectUsages:    reflects,
		EntryPointUsages: entrypoints,
	}
}

func findUnsoundDataflowFeatures(f *ssa.Function) UnsoundDataflowFeatures {
	var recovers []token.Position
	var gos []token.Position
	defersUnbounded := false

	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		deferRes := defers.AnalyzeFunction(f, config.NewLogger(config.ErrLevel))
		if !deferRes.DeferStackBounded {
			defersUnbounded = true
		}
		if isRecoverInstr(instr) {
			pos := f.Prog.Fset.Position(instr.Pos())
			if !slices.Contains(recovers, pos) {
				recovers = append(recovers, pos)
			}
		} else if isGoroutineInstr(instr) {
			pos := f.Prog.Fset.Position(instr.Pos())
			if !slices.Contains(gos, pos) {
				gos = append(gos, pos)
			}
		}
	})

	return UnsoundDataflowFeatures{
		RecoverUsages:      recovers,
		GoUsages:           gos,
		HasUnboundedDefers: defersUnbounded,
	}
}

// isGlobalInstr returns true if any of instr's operands is a global.
// A global means that it is a non-static global variable.
func isGlobalInstr(instr ssa.Instruction) bool {
	var operands []*ssa.Value
	operands = instr.Operands(operands)
	for _, operand := range operands {
		if _, ok := (*operand).(*ssa.Global); ok {
			return true
		}
	}

	return false
}

func isEntrypoint(instr ssa.Instruction, specs []dataflow.ScanningSpec) bool {
	instrNode, isNode := instr.(ssa.Node)
	if !isNode {
		return false
	}
	for _, spec := range specs {
		if _, ok := spec.IsEntryPointSsa(instrNode); ok {
			return true
		}
	}
	return false
}

type unsafeOrReflect struct {
	isUnsafe  bool
	isReflect bool
}

// isUnsafeOrReflectInstr returns true if instr uses the unsafe or reflect package.
//
// TODO This is taken from analysis/dataflow/report.go and should eventually be refactored into a
// common package.
func isUnsafeOrReflectInstr(instr ssa.Instruction) unsafeOrReflect {
	switch instr := instr.(type) {
	case ssa.CallInstruction:
		call := instr.Common()
		if call == nil {
			return unsafeOrReflect{isUnsafe: false, isReflect: false}
		}

		switch val := call.Value.(type) {
		case *ssa.Function:
			pkg := lang.PkgPathFromFunction(val)
			// Call a function from the unsafe package.
			if strings.HasPrefix(pkg, "unsafe") {
				return unsafeOrReflect{isUnsafe: true, isReflect: false}
			}
			// Call a function from the reflect package.
			if strings.HasPrefix(pkg, "reflect") {
				return unsafeOrReflect{isUnsafe: false, isReflect: true}
			}
		case *ssa.Builtin:
			// Call an unsafe builtin function.
			if _, ok := unsafeBuiltins[val.Name()]; ok {
				return unsafeOrReflect{isUnsafe: true, isReflect: false}
			}
		}
	case *ssa.Alloc:
		typ := instr.Type().Underlying()
		if typ == nil {
			return unsafeOrReflect{isUnsafe: false, isReflect: false}
		}
		pkg := lang.GetPackageOfType(typ)
		if pkg == nil {
			return unsafeOrReflect{isUnsafe: false, isReflect: false}
		}
		// Allocate an object of an unsafe type.
		if strings.HasPrefix(pkg.Name(), "unsafe") {
			return unsafeOrReflect{isUnsafe: true, isReflect: false}
		}
		// Allocate an object of a reflect type.
		if strings.HasPrefix(pkg.Name(), "reflect") {
			return unsafeOrReflect{isUnsafe: false, isReflect: true}
		}
	case *ssa.Convert:
		typ := instr.Type()
		if typ == nil {
			return unsafeOrReflect{isUnsafe: false, isReflect: false}
		}
		// Convert data to an unsafe pointer.
		if strings.Contains(typ.String(), "unsafe") {
			return unsafeOrReflect{isUnsafe: true, isReflect: false}
		}
	}

	return unsafeOrReflect{isUnsafe: false, isReflect: false}
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

// isGoroutineInstr returns true if instr is a goroutine call.
func isGoroutineInstr(instr ssa.Instruction) bool {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return false
	}

	_, ok = call.(*ssa.Go)
	return ok
}

// isRecoverInstr returns true if instr is a recover call.
func isRecoverInstr(instr ssa.Instruction) bool {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return false
	}

	if call == nil || call.Common() == nil || call.Common().Value == nil {
		return false
	}

	return call.Common().Value.Name() == "recover"
}
