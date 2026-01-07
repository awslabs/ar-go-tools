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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
)

var allowedReflect = []lang.UnsafeOrReflect{
	lang.UnsafeOrReflect{IsReflect: true, Name: "TypeOf", Pkg: "reflect"},
}

// findUnsoundCheckFeatures returns the Go features used in all functions reachable from function f
// according to callgraph cg that make the check analysis unsound.
//
// For efficiency, it only returns the first 5 unsound features.
//
//gocyclo:ignore
func findUnsoundCheckFeatures(
	s *State,
	f *ssa.Function,
	specs []dataflow.ScanningSpec,
) UnsoundCheckFeatures {
	cg := s.PointerAnalysis.CallGraph
	queue := []*callgraph.Node{cg.Nodes[f]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})
	var globals []token.Position
	var unsafes []token.Position
	var reflects []token.Position
	var entrypoints []token.Position

	// Callgraph traversal
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if _, ok := seen[node]; ok || node.Func == nil {
			continue
		}
		seen[node] = struct{}{}
		// Skip the function if it has a summary and we are not ignoring predefined functions.
		if !s.Config.CheckIgnoresPredefined && summaries.FnHasSummaries(node.Func) {
			s.Logger.Tracef("%s has summaries.", node.Func.String())
			continue
		} else {
			s.Logger.Tracef("%s does not have a summary.", node.Func.String())
		}
		// A function may be visited multiple times in different calling contexts so only analyze
		// each function once.
		if _, ok := seenFunc[node.Func]; ok {
			continue
		}
		seenFunc[node.Func] = struct{}{}

		lang.IterateInstructions(node.Func, func(_ int, instr ssa.Instruction) {
			prog := instr.Parent().Prog
			if isGlobalInstr(s, instr) {
				pos := prog.Fset.Position(instr.Pos())
				// This is fast because len(globals) is never greater than 5 or so.
				if !slices.Contains(globals, pos) {
					globals = append(globals, pos)
				}
			} else if isUnsafeOrReflect := lang.IsUnsafeOrReflectInstr(instr); isUnsafeOrReflect.IsUnsafe {
				pos := prog.Fset.Position(instr.Pos())
				if !slices.Contains(unsafes, pos) {
					unsafes = append(unsafes, pos)
				}
			} else if isUnsafeOrReflect.IsReflect {
				if slices.Contains(allowedReflect, isUnsafeOrReflect) {
					return
				}
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
func isGlobalInstr(s *State, instr ssa.Instruction) bool {
	var operands []*ssa.Value
	operands = instr.Operands(operands)
	for _, operand := range operands {
		if glob, ok := (*operand).(*ssa.Global); ok && isGlobalWrittenOutsideInit(s, glob) {
			return true
		}
	}
	return false
}

func isGlobalWrittenOutsideInit(s *State, glob *ssa.Global) bool {
	globNodes := s.Globals[glob]
	for writeLoc := range globNodes.WriteLocations {
		if writeLoc.ParentName() != "init" {
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
