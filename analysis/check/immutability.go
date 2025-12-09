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

// import (
// 	"context"
// 	"fmt"
// 	"go/types"
// 	"time"

// 	"golang.org/x/tools/container/intsets"
// 	"golang.org/x/tools/go/ssa"

// 	"github.com/awslabs/ar-go-tools/analysis/dataflow"
// 	"github.com/awslabs/ar-go-tools/analysis/lang"
// 	"github.com/awslabs/ar-go-tools/analysis/summaries"
// 	"github.com/awslabs/ar-go-tools/internal/pointer"
// )

// TODO Make sure the immutability analysis is linear: maybe when I hit a call instruction, analyze the callee (instead of computing transitively reachable callees up front)
// func checkSummaryImmutability(
// 	ctx context.Context, s *State, g *dataflow.SummaryGraph,
// 	want summaries.DetailedSummary, start time.Time,
// ) (SoundnessResult, error) {
// 	general := newMostGeneralDetailedSummary(g.Parent, true)
// 	fname := g.Parent.RelString(nil)
// 	// badFlows are the flows in want that are not in the most-general summary
// 	isSound, badFlows := isSummarySubset(fname, general, want)
// 	if isSound {
// 		return SoundnessResult{
// 			Fn:       fname,
// 			Want:     want,
// 			Got:      want,
// 			IsSound:  true,
// 			BadFlows: nil,
// 			Time:     time.Since(start),
// 		}, nil
// 	}

// 	sound := true
// 	var resBad []Flow
// 	for _, flow := range badFlows {
// 		isBad, err := isBadFlowImmutability(s, flow)
// 		if err != nil {
// 			return SoundnessResult{}, fmt.Errorf("failed to check bad flow %v via immutability: %v", flow, err)
// 		}
// 		// If the analysis failed to disprove a single bad flow, don't bother checking the rest since the
// 		// summary is unsound
// 		if isBad {
// 			resBad = append(resBad, flow)
// 			sound = false
// 			break
// 		}
// 	}

// 	return SoundnessResult{
// 		Fn:       fname,
// 		Want:     want,
// 		Got:      general,
// 		IsSound:  sound,
// 		BadFlows: resBad,
// 		Time:     time.Since(start),
// 	}, nil
// }

// // isBadFlowImmutability returns true if flow.To is written to (modified) in any way.
// //
// // If flow.To is pointer-like, then it uses the pointer analysis to detect any writes to the
// // value(s)'s underlying memory in the flow's function or any of its transitively-reachable callees.
// //
// // Otherwise, it detects any explicit writes to flow.To's value(s) in the flow's function.
// // There is no need to analyze any callees because the value is stack allocated and therefore cannot
// // be modified outside of the function.
// func isBadFlowImmutability(s *State, flow Flow) (bool, error) {
// 	// TODO Avoid converting from summaries.SummaryNode to dataflow.GraphNode each time
// 	f, err := functionOfName(s, flow.Fn)
// 	if err != nil {
// 		return true, err
// 	}
// 	g, ok := s.FlowGraph.Summaries[f]
// 	if !ok {
// 		return true, fmt.Errorf("failed to find summary for function %s", f)
// 	}
// 	vals := outputVals(g, flow)
// 	for _, val := range vals {
// 		if isPointerLike(val.Type()) {
// 			ids := nodeIds(s.cache, val)
// 		} else {
// 			// reaching defs
// 		}
// 	}

// 	return false, nil
// }

// func outputVals(g *dataflow.SummaryGraph, flow Flow) []ssa.Value {
// 	var vals []ssa.Value
// 	to := findNode(g, flow.To)
// 	switch to := to.(type) {
// 	case *dataflow.ParamNode:
// 		vals = append(vals, to.SsaNode())
// 	case *dataflow.ReturnValNode:
// 		for retInstr := range g.Returns {
// 			retInstr, ok := retInstr.(*ssa.Return)
// 			if !ok {
// 				panic(fmt.Errorf("invalid return instruction %v", retInstr))
// 			}
// 			val := retInstr.Results[to.Index()]
// 			vals = append(vals, val)
// 		}
// 	}

// 	return vals
// }

// func nodeIds(c *aliasCache, val ssa.Value) *intsets.Sparse {
// 	ids := &intsets.Sparse{}
// 	objs := c.Objects(val)
// 	// initialize points-to-set of entrypoint
// 	for obj := range objs {
// 		switch data := obj.Data().(type) {
// 		case *ssa.MakeInterface:
// 			dataObjs := c.Objects(data.X) // get the objects of the concrete struct
// 			for obj := range dataObjs {
// 				for _, id := range obj.NodeIDs() {
// 					ids.Insert(int(id))
// 				}
// 			}
// 		default:
// 			for _, id := range obj.NodeIDs() {
// 				ids.Insert(int(id))
// 			}
// 		}
// 	}

// 	return ids
// }

// // findModifications adds:
// //   - all write instructions to a member of the entrypoint's
// //     points-to-set to s.entryWrites
// //   - all read instructions from a member of the entrypoint's points-to-set to
// //     s.entryReads
// //
// // Algorithm:
// //  1. For each write and read instruction, compute the objects that the value written to
// //     or read from can point to.
// //  2. For each object, if the object is a member of the entrypoint's points-to-set,
// //     then add the instruction to s.entryWrites or s.entryReads.
// //  3. For each allocation instruction, compute the objects that the resulting
// //     value can point to.
// func (s *State) findModifications() {
// 	for _, fna := range s.funcsToAnalyze {
// 		s.findWrites(fna)
// 		s.findReads(fna)
// 		s.findAllocs(fna)
// 	}
// }

// func (s *State) findWrites(fna *funcToAnalyze) {
// 	for instr := range fna.writeInstrs {
// 		write, ok := ptrWrittenTo(instr)
// 		if !ok {
// 			continue
// 		}
// 		// We assume that errors are only used as values
// 		if isAllocatedErrorType(write.Target) {
// 			continue
// 		}
// 		pos := write.Pos
// 		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
// 			s.log.Tracef("//argot:ignore write at %s", pos)
// 			continue
// 		}

// 		mobjs := s.Objects(write.Target)
// 		for mobj := range mobjs {
// 			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
// 				s.entryWrites = append(s.entryWrites, write)
// 				break
// 			}
// 		}
// 	}
// }

// //gocyclo:ignore
// func (s *State) findReads(fna *funcToAnalyze) {
// 	for instr := range fna.readInstrs {
// 		read, ok := ptrsReadFrom(instr.Instruction, instr.Pos)
// 		if !ok {
// 			continue
// 		}

// 		pos := read.Pos
// 		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
// 			s.log.Tracef("//argot:ignore read at %s", pos)
// 			continue
// 		}

// 		var aliasedReadVals []ssa.Value
// 		for _, rval := range read.Values {
// 			if !pointer.CanPoint(rval.Type()) {
// 				continue
// 			}
// 			// We assume that errors are only used as values
// 			if isAllocatedErrorType(rval) {
// 				continue
// 			}

// 			if rval == s.entry {
// 				s.log.Tracef("rvalue %v of read instruction %v is the same as entrypoint: skipping...", rval, instr)
// 				continue
// 			}

// 			mobjs := s.Objects(rval)
// 			for mobj := range mobjs {
// 				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
// 					if val, ok := mobj.Data().(ssa.Value); ok {
// 						// HACK Don't add reads to an object of the same type as the entrypoint
// 						// This is sound because we validate that an entrypoint
// 						// struct never has a field with the same type as it.
// 						typ := val.Type().Underlying()
// 						_, isInterface := typ.(*types.Interface)
// 						_, isStruct := typ.(*types.Struct)
// 						if isInterface || isStruct {
// 							if typ == s.entry.Type().Underlying() {
// 								s.log.Debugf("skipping read of pointer object %v (%v): has the same type as entrypoint: %v\n", mobj, val, typ)
// 								continue
// 							}
// 						}
// 					}
// 					aliasedReadVals = append(aliasedReadVals, rval)
// 					break
// 				}
// 			}
// 		}

// 		if len(aliasedReadVals) > 0 {
// 			s.entryReads = append(s.entryReads, ptr.Read{Instruction: read.Instruction, Values: aliasedReadVals, Pos: read.Pos})
// 		}
// 	}
// }

// func (s *State) findAllocs(fna *funcToAnalyze) {
// 	for instr := range fna.allocInstrs {
// 		val := instr.Instruction.(ssa.Value) // should not panic
// 		if s.shouldFilterValue(val) {
// 			s.log.Tracef("lvalue %v of alloc instruction %v filtered by spec: skipping...", val, instr)
// 			continue
// 		}
// 		pos := instr.Pos
// 		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
// 			s.log.Tracef("//argot:ignore alloc at %s", pos)
// 			continue
// 		}

// 		mobjs := s.Objects(val)
// 		for mobj := range mobjs {
// 			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
// 				alloc := Alloc{Instr: instr, Value: val}
// 				s.entryAllocs = append(s.entryAllocs, alloc)
// 				break
// 			}
// 		}
// 	}
// }

// type funcToAnalyze struct {
// 	writeInstrs map[ssa.Instruction]struct{}
// 	readInstrs  map[ssa.Instruction]struct{}
// 	vals        map[ssa.Value]struct{}
// }

// func newFuncToAnalyze(fn *ssa.Function) *funcToAnalyze {
// 	vals := make(map[ssa.Value]struct{})
// 	addValuesOfFn(fn, vals)
// 	writeInstrs := make(map[ssa.Instruction]struct{})
// 	readInstrs := make(map[ssa.Instruction]struct{})
// 	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
// 		if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
// 			return
// 		}

// 		switch instr.(type) {
// 		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
// 			writeInstrs[instr] = struct{}{}
// 			readInstrs[instr] = struct{}{}
// 		default:
// 			readInstrs[instr] = struct{}{}
// 		}
// 	})

// 	return &funcToAnalyze{
// 		vals:        vals,
// 		writeInstrs: writeInstrs,
// 		readInstrs:  readInstrs,
// 	}
// }

// func addValuesOfFn(fn *ssa.Function, vals map[ssa.Value]struct{}) {
// 	lang.IterateValues(fn, func(_ int, val ssa.Value) {
// 		if val == nil || val.Parent() == nil {
// 			return
// 		}
// 		vals[val] = struct{}{}
// 	})
// }

// func isAllocatedErrorType(val ssa.Value) bool {
// 	// catch cases like: change interface any <- error (err)
// 	if ci, ok := val.(*ssa.ChangeInterface); ok {
// 		val = ci.X
// 	}

// 	typ := val.Type()
// 	switch t := typ.(type) {
// 	case *types.Pointer:
// 		typ = t.Elem().Underlying()
// 	case *types.Interface:
// 		typ = t.Underlying()
// 	}

// 	return types.AssignableTo(typ, types.Universe.Lookup("error").Type())
// }
