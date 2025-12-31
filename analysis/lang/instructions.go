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
	"context"
	"go/types"
	"strings"

	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// This implementation is inspired from the Go ssa interpreter
// https://cs.opensource.google/go/x/tools/+/refs/tags/v0.2.0:go/ssa/interp/interp.go
// Its main use is to provide "documentation" on what are the SSA instructions

// An InstrOp must implement methods for ALL possible SSA instructions
type InstrOp interface {
	DoDebugRef(context.Context, *ssa.DebugRef)
	DoUnOp(context.Context, *ssa.UnOp)
	DoBinOp(context.Context, *ssa.BinOp)
	DoCall(context.Context, *ssa.Call)
	DoChangeInterface(context.Context, *ssa.ChangeInterface)
	DoChangeType(context.Context, *ssa.ChangeType)
	DoConvert(context.Context, *ssa.Convert)
	DoSliceArrayToPointer(context.Context, *ssa.SliceToArrayPointer)
	DoMakeInterface(context.Context, *ssa.MakeInterface)
	DoExtract(context.Context, *ssa.Extract)
	DoSlice(context.Context, *ssa.Slice)
	DoReturn(context.Context, *ssa.Return)
	DoRunDefers(context.Context, *ssa.RunDefers)
	DoPanic(context.Context, *ssa.Panic)
	DoSend(context.Context, *ssa.Send)
	DoStore(context.Context, *ssa.Store)
	DoIf(context.Context, *ssa.If)
	DoJump(context.Context, *ssa.Jump)
	DoDefer(context.Context, *ssa.Defer)
	DoGo(context.Context, *ssa.Go)
	DoMakeChan(context.Context, *ssa.MakeChan)
	DoAlloc(context.Context, *ssa.Alloc)
	DoMakeSlice(context.Context, *ssa.MakeSlice)
	DoMakeMap(context.Context, *ssa.MakeMap)
	DoRange(context.Context, *ssa.Range)
	DoNext(context.Context, *ssa.Next)
	DoFieldAddr(context.Context, *ssa.FieldAddr)
	DoField(context.Context, *ssa.Field)
	DoIndexAddr(context.Context, *ssa.IndexAddr)
	DoIndex(context.Context, *ssa.Index)
	DoLookup(context.Context, *ssa.Lookup)
	DoMapUpdate(context.Context, *ssa.MapUpdate)
	DoTypeAssert(context.Context, *ssa.TypeAssert)
	DoMakeClosure(context.Context, *ssa.MakeClosure)
	DoPhi(context.Context, *ssa.Phi)
	DoSelect(context.Context, *ssa.Select)
}

// InstrSwitch is mainly a map from the different instructions to the methods of the visitor.
//
//gocyclo:ignore
func InstrSwitch(ctx context.Context, visitor InstrOp, instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.DebugRef:
	// no-op
	case *ssa.UnOp:
		visitor.DoUnOp(ctx, instr)
	case *ssa.BinOp:
		visitor.DoBinOp(ctx, instr)
	case *ssa.Call:
		visitor.DoCall(ctx, instr)
	case *ssa.ChangeInterface:
		visitor.DoChangeInterface(ctx, instr)
	case *ssa.ChangeType:
		visitor.DoChangeType(ctx, instr)
	case *ssa.Convert:
		visitor.DoConvert(ctx, instr)
	case *ssa.SliceToArrayPointer:
		visitor.DoSliceArrayToPointer(ctx, instr)
	case *ssa.Extract:
		visitor.DoExtract(ctx, instr)
	case *ssa.Slice:
		visitor.DoSlice(ctx, instr)
	case *ssa.Return:
		visitor.DoReturn(ctx, instr)
	case *ssa.RunDefers:
		visitor.DoRunDefers(ctx, instr)
	case *ssa.Panic:
		visitor.DoPanic(ctx, instr)
	case *ssa.Send:
		visitor.DoSend(ctx, instr)
	case *ssa.Store:
		visitor.DoStore(ctx, instr)
	case *ssa.If:
		visitor.DoIf(ctx, instr)
	case *ssa.Jump:
		visitor.DoJump(ctx, instr)
	case *ssa.Defer:
		visitor.DoDefer(ctx, instr)
	case *ssa.Go:
		visitor.DoGo(ctx, instr)
	case *ssa.MakeChan:
		visitor.DoMakeChan(ctx, instr)
	case *ssa.Alloc:
		visitor.DoAlloc(ctx, instr)
	case *ssa.MakeSlice:
		visitor.DoMakeSlice(ctx, instr)
	case *ssa.MakeMap:
		visitor.DoMakeMap(ctx, instr)
	case *ssa.Range:
		visitor.DoRange(ctx, instr)
	case *ssa.Next:
		visitor.DoNext(ctx, instr)
	case *ssa.FieldAddr:
		visitor.DoFieldAddr(ctx, instr)
	case *ssa.Field:
		visitor.DoField(ctx, instr)
	case *ssa.IndexAddr:
		visitor.DoIndexAddr(ctx, instr)
	case *ssa.Index:
		visitor.DoIndex(ctx, instr)
	case *ssa.Lookup:
		visitor.DoLookup(ctx, instr)
	case *ssa.MapUpdate:
		visitor.DoMapUpdate(ctx, instr)
	case *ssa.TypeAssert:
		visitor.DoTypeAssert(ctx, instr)
	case *ssa.MakeClosure:
		visitor.DoMakeClosure(ctx, instr)
	case *ssa.MakeInterface:
		visitor.DoMakeInterface(ctx, instr)
	case *ssa.Phi:
		visitor.DoPhi(ctx, instr)
	case *ssa.Select:
		visitor.DoSelect(ctx, instr)
	default:
		panic(instr)
	}
}

// Utilities for working with blocks and instructions

// IndexInEnclosingBlock returns the parent block of an instruction with the index of the instruction in it.
//
//	If the instruction is nil, or the parent function is nil, then it returns nil.
func IndexInEnclosingBlock(instr ssa.Instruction) (*ssa.BasicBlock, int) {
	if instr == nil || instr.Block() == nil {
		return nil, 0
	}
	block := instr.Block()
	for i, blockInstr := range block.Instrs {
		if blockInstr == instr {
			return block, i
		}
	}
	// Not found in own parent?
	panic("internal SSA representation broken.")
}

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

// Param is a parameter of a function.
type Param struct {
	Var        *types.Var
	IsVariadic bool
}

// GetParams returns the callee params of instr.
func GetParams(instr ssa.CallInstruction) []Param {
	var params []Param
	sig := instr.Common().Signature()
	if sig.Recv() != nil {
		// The first parameter of a method call is the receiver
		param := Param{
			Var:        sig.Recv(),
			IsVariadic: false,
		}
		params = append(params, param)
	}
	for i := 0; i < sig.Params().Len(); i++ {
		p := sig.Params().At(i)
		isVariadic := false
		if sig.Variadic() && i == sig.Params().Len()-1 {
			isVariadic = true
		}
		param := Param{
			Var:        p,
			IsVariadic: isVariadic,
		}
		params = append(params, param)
	}

	return params
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

// UnsafeOrReflect indicates whether a function uses unsafe operations or reflection.
type UnsafeOrReflect struct {
	IsUnsafe  bool
	IsReflect bool
}

// IsUnsafeOrReflectInstr returns true if instr uses the unsafe or reflect package.
//
//gocyclo:ignore
func IsUnsafeOrReflectInstr(instr ssa.Instruction) UnsafeOrReflect {
	switch instr := instr.(type) {
	case ssa.CallInstruction:
		call := instr.Common()
		if call == nil {
			return UnsafeOrReflect{IsUnsafe: false, IsReflect: false}
		}

		switch val := call.Value.(type) {
		case *ssa.Function:
			pkg := PkgPathFromFunction(val)
			// Call a function from the unsafe package.
			if strings.HasPrefix(pkg, "unsafe") {
				return UnsafeOrReflect{IsUnsafe: true, IsReflect: false}
			}
			// Call a function from the reflect package.
			if strings.HasPrefix(pkg, "reflect") {
				return UnsafeOrReflect{IsUnsafe: false, IsReflect: true}
			}
		case *ssa.Builtin:
			// Call an unsafe builtin function.
			if _, ok := UnsafeBuiltins[val.Name()]; ok {
				return UnsafeOrReflect{IsUnsafe: true, IsReflect: false}
			}
		}
	case *ssa.Alloc:
		typ := instr.Type().Underlying()
		if typ == nil {
			return UnsafeOrReflect{IsUnsafe: false, IsReflect: false}
		}
		pkg := GetPackageOfType(typ)
		if pkg == nil {
			return UnsafeOrReflect{IsUnsafe: false, IsReflect: false}
		}
		// Allocate an object of an unsafe type.
		if strings.HasPrefix(pkg.Name(), "unsafe") {
			return UnsafeOrReflect{IsUnsafe: true, IsReflect: false}
		}
		// Allocate an object of a reflect type.
		if strings.HasPrefix(pkg.Name(), "reflect") {
			return UnsafeOrReflect{IsUnsafe: false, IsReflect: true}
		}
	case *ssa.Convert:
		typ := instr.Type()
		if typ == nil {
			return UnsafeOrReflect{IsUnsafe: false, IsReflect: false}
		}
		// Convert data to an unsafe pointer.
		if strings.Contains(typ.String(), "unsafe") {
			return UnsafeOrReflect{IsUnsafe: true, IsReflect: false}
		}
	}

	return UnsafeOrReflect{IsUnsafe: false, IsReflect: false}
}
