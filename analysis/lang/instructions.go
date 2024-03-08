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
	"fmt"

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

// FirstInstr returns the first instruction in a block. There is always a first instruction for a reachable block.
// Returns nil for an empty block (a block can be empty if it is non-reachable)
func FirstInstr(block *ssa.BasicBlock) ssa.Instruction {
	if len(block.Instrs) == 0 {
		return nil
	}
	return block.Instrs[0]
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

// FnHasGlobal returns true if fn has a global value.
func FnHasGlobal(fn *ssa.Function) bool {
	res := false
	IterateValues(fn, func(_ int, value ssa.Value) {
		if _, ok := value.(*ssa.Global); ok {
			res = true
			return
		}
	})

	return res
}

// FnReadsFrom returns true if an instruction in fn reads from val.
func FnReadsFrom(fn *ssa.Function, val ssa.Value) bool {
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if _, ok := InstrReadsInto(instr, val); ok {
				return true
			}
		}
	}

	return false
}

// InstrReadsInto returns true and the value val is read into (LHS of read) if instr reads from val.
func InstrReadsInto(instr ssa.Instruction, val ssa.Value) (ssa.Value, bool) {
	switch instr := instr.(type) {
	case *ssa.UnOp:
		if instr.X == val {
			return instr, true
		}
	case *ssa.BinOp:
		if instr.X == val || instr.Y == val {
			return instr, true
		}
	case *ssa.Store:
		// a store "aliases" val to instr.Addr
		switch addr := instr.Addr.(type) {
		// Special store
		case *ssa.FieldAddr:
			if addr.X == val {
				// e.g. *struct.Field = val
				// value read into is *struct which is addr.X
				return addr.X, true
			}
		}

		if instr.Val == val {
			return instr.Addr, true
		}
	case *ssa.Field:
		if instr.X == val {
			return instr, true
		}
	case *ssa.FieldAddr:
		if instr.X == val {
			return instr, true
		}
		// special case: FieldAddr writes to itself?
		if fa, ok := val.(*ssa.FieldAddr); ok {
			if instr.X == fa.X && instr.Field == fa.Field {
				return instr, true
			}
		}
	case *ssa.Convert:
		if instr.X == val {
			return instr, true
		}
	case *ssa.Call:
		if instr.Call.Value == val {
			return instr, true
		}

		for _, arg := range GetArgs(instr) {
			if arg == val {
				return instr, true
			}
		}
	}

	return val, false
}

// FnWritesTo returns true if an instruction in fn writes to val.
func FnWritesTo(fn *ssa.Function, val ssa.Value) bool {
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if _, ok := InstrWritesToVal(instr, val); ok {
				return true
			}
		}
	}

	return false
}

// InstrWritesToVal returns the value written (RHS) and true if instr writes to val.
func InstrWritesToVal(instr ssa.Instruction, val ssa.Value) (ssa.Value, bool) {
	switch instr := instr.(type) {
	case *ssa.Store:
		if instr.Addr == val {
			return instr.Val, true
		}
	case *ssa.MapUpdate:
		if instr.Map == val {
			return instr.Value, true
		}
	case *ssa.Send:
		if instr.Chan == val {
			return instr.X, true
		}
	}

	return nil, false
}

// InstrWritesTo return true if val is the lvalue of write instruction instr.
func InstrWritesTo(instr ssa.Instruction, val ssa.Value) bool {
	switch instr := instr.(type) {
	case *ssa.Store:
		return instr.Addr == val
	case *ssa.MapUpdate:
		return instr.Map == val
	case *ssa.Send:
		return instr.Chan == val
	// case ssa.Value:
	// 	return instr == val
	default:
		return false
	}
}

// InstrWritesFrom returns the value written (RHS) and true if instr is a write instruction.
func InstrWritesFrom(instr ssa.Instruction) (ssa.Value, bool) {
	switch instr := instr.(type) {
	case *ssa.Store:
		return instr.Val, true
	case *ssa.MapUpdate:
		return instr.Value, true
	case *ssa.Send:
		return instr.X, true
	default:
		return nil, false
	}
}

// FmtInstr returns a string formatting instr to show the instruction type and operands.
// This is used mostly for debugging.
func FmtInstr(instr ssa.Instruction) string {
	switch instr := instr.(type) {
	case *ssa.FieldAddr:
		return fmt.Sprintf("[%v = %v (%T)]", instr.Name(), instr, instr)
	case *ssa.Store:
		return fmt.Sprintf("[*%v = %v (%T)]", instr.Addr.Name(), instr.Val.Name(), instr)
	case *ssa.UnOp:
		return fmt.Sprintf("[%v = %v%v (%T)]", instr.Name(), instr.Op, instr.X.Name(), instr)
	default:
		return fmt.Sprintf("[%v (%T)]", instr.String(), instr)
	}
}
