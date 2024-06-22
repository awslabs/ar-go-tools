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

// Package lang provides functions to operate on the SSA representation of a program.
// It provides an interface to implement visitors for SSA instructions.
package lang

import (
	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// This implementation is inspired from the Go ssa interpreter
// https://cs.opensource.google/go/x/tools/+/refs/tags/v0.2.0:go/ssa/interp/interp.go
// Its main use is to provide "documentation" on what are the SSA instructions

// An InstrOp must implement methods for ALL possible SSA instructions
type InstrOp interface {
	DoDebugRef(*ssa.DebugRef)
	DoUnOp(*ssa.UnOp)
	DoBinOp(*ssa.BinOp)
	DoCall(*ssa.Call)
	DoChangeInterface(*ssa.ChangeInterface)
	DoChangeType(*ssa.ChangeType)
	DoConvert(*ssa.Convert)
	DoSliceArrayToPointer(*ssa.SliceToArrayPointer)
	DoMakeInterface(*ssa.MakeInterface)
	DoExtract(*ssa.Extract)
	DoSlice(*ssa.Slice)
	DoReturn(*ssa.Return)
	DoRunDefers(*ssa.RunDefers)
	DoPanic(*ssa.Panic)
	DoSend(*ssa.Send)
	DoStore(*ssa.Store)
	DoIf(*ssa.If)
	DoJump(*ssa.Jump)
	DoDefer(*ssa.Defer)
	DoGo(*ssa.Go)
	DoMakeChan(*ssa.MakeChan)
	DoAlloc(*ssa.Alloc)
	DoMakeSlice(*ssa.MakeSlice)
	DoMakeMap(*ssa.MakeMap)
	DoRange(*ssa.Range)
	DoNext(*ssa.Next)
	DoFieldAddr(*ssa.FieldAddr)
	DoField(*ssa.Field)
	DoIndexAddr(*ssa.IndexAddr)
	DoIndex(*ssa.Index)
	DoLookup(*ssa.Lookup)
	DoMapUpdate(*ssa.MapUpdate)
	DoTypeAssert(*ssa.TypeAssert)
	DoMakeClosure(*ssa.MakeClosure)
	DoPhi(*ssa.Phi)
	DoSelect(*ssa.Select)
}

// InstrSwitch is mainly a map from the different instructions to the methods of the visitor.
//
//gocyclo:ignore
func InstrSwitch(visitor InstrOp, instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.DebugRef:
	// no-op
	case *ssa.UnOp:
		visitor.DoUnOp(instr)
	case *ssa.BinOp:
		visitor.DoBinOp(instr)
	case *ssa.Call:
		visitor.DoCall(instr)
	case *ssa.ChangeInterface:
		visitor.DoChangeInterface(instr)
	case *ssa.ChangeType:
		visitor.DoChangeType(instr)
	case *ssa.Convert:
		visitor.DoConvert(instr)
	case *ssa.SliceToArrayPointer:
		visitor.DoSliceArrayToPointer(instr)
	case *ssa.Extract:
		visitor.DoExtract(instr)
	case *ssa.Slice:
		visitor.DoSlice(instr)
	case *ssa.Return:
		visitor.DoReturn(instr)
	case *ssa.RunDefers:
		visitor.DoRunDefers(instr)
	case *ssa.Panic:
		visitor.DoPanic(instr)
	case *ssa.Send:
		visitor.DoSend(instr)
	case *ssa.Store:
		visitor.DoStore(instr)
	case *ssa.If:
		visitor.DoIf(instr)
	case *ssa.Jump:
		visitor.DoJump(instr)
	case *ssa.Defer:
		visitor.DoDefer(instr)
	case *ssa.Go:
		visitor.DoGo(instr)
	case *ssa.MakeChan:
		visitor.DoMakeChan(instr)
	case *ssa.Alloc:
		visitor.DoAlloc(instr)
	case *ssa.MakeSlice:
		visitor.DoMakeSlice(instr)
	case *ssa.MakeMap:
		visitor.DoMakeMap(instr)
	case *ssa.Range:
		visitor.DoRange(instr)
	case *ssa.Next:
		visitor.DoNext(instr)
	case *ssa.FieldAddr:
		visitor.DoFieldAddr(instr)
	case *ssa.Field:
		visitor.DoField(instr)
	case *ssa.IndexAddr:
		visitor.DoIndexAddr(instr)
	case *ssa.Index:
		visitor.DoIndex(instr)
	case *ssa.Lookup:
		visitor.DoLookup(instr)
	case *ssa.MapUpdate:
		visitor.DoMapUpdate(instr)
	case *ssa.TypeAssert:
		visitor.DoTypeAssert(instr)
	case *ssa.MakeClosure:
		visitor.DoMakeClosure(instr)
	case *ssa.MakeInterface:
		visitor.DoMakeInterface(instr)
	case *ssa.Phi:
		visitor.DoPhi(instr)
	case *ssa.Select:
		visitor.DoSelect(instr)
	default:
		panic(instr)
	}
}

// Utilities for working with blocks and instructions

// LastInstr returns the last instruction in a block. There is always a last instruction for a reachable block.
// Returns nil for an empty block (a block can be empty if it is non-reachable)
func LastInstr(block *ssa.BasicBlock) ssa.Instruction {
	if len(block.Instrs) == 0 {
		return nil
	}
	return block.Instrs[len(block.Instrs)-1]
}

// GetArgs returns the arguments of a function call including the receiver when the function called is a method.
// More precisely, it returns instr.Common().Args, but prepends instr.Common().Value if the call is "invoke" mode.
func GetArgs(instr ssa.CallInstruction) []ssa.Value {
	var args []ssa.Value
	if instr.Common().IsInvoke() {
		args = append(args, instr.Common().Value)
	}
	args = append(args, instr.Common().Args...)
	return args
}

// InstrMethodKey return a method key (as used in the analyzer state for indexing interface methods) if the instruction
// calls a method from an interface
// Returns an optional value
// TODO: this may not be idiomatic but I'm testing this "Optional" implementation
func InstrMethodKey(instr ssa.CallInstruction) fn.Optional[string] {
	methodFunc := instr.Common().Method
	if methodFunc != nil {
		methodKey := instr.Common().Value.Type().String() + "." + methodFunc.Name()
		return fn.Some(methodKey)
	}

	return fn.None[string]()
}

// FnReadsFrom returns true if an instruction in fn reads from val.
//
//gocyclo:ignore
func FnReadsFrom(fn *ssa.Function, val ssa.Value) bool {
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			switch instr := instr.(type) {
			case *ssa.UnOp:
				if instr.X == val {
					return true
				}
			case *ssa.BinOp:
				if instr.X == val || instr.Y == val {
					return true
				}
			case *ssa.Store:
				// Special store
				switch addr := instr.Addr.(type) {
				case *ssa.FieldAddr:
					if addr.X == val {
						return true
					}
				}

				if instr.Val == val {
					return true
				}
			case *ssa.MapUpdate:
				if instr.Value == val {
					return true
				}
			case *ssa.Send:
				if instr.X == val {
					return true
				}
			case *ssa.Field:
				if instr.X == val {
					return true
				}
			case *ssa.FieldAddr:
				if instr.X == val {
					return true
				}
			case *ssa.Convert:
				if instr.X == val {
					return true
				}
			}
		}
	}

	return false
}

// FnWritesTo returns true if an instruction in fn writes to val.
func FnWritesTo(fn *ssa.Function, val ssa.Value) bool {
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			switch instr := instr.(type) {
			case *ssa.Store:
				if instr.Addr == val {
					return true
				}
			case *ssa.MapUpdate:
				if instr.Map == val {
					return true
				}
			case *ssa.Send:
				if instr.Chan == val {
					return true
				}
			}
		}
	}

	return false
}
