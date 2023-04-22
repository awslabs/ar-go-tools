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

package lang

import (
	"golang.org/x/tools/go/ssa"
)

// pathSensitiveInstrOpTemplate is a template implementation for a path sensitive instruction operation
// Implementing this interface forces the programmer to think about every possible instruction.
// The path sensitive operations can be omitted to implement some InstrOp only
type pathSensitiveInstrOpTemplate struct{}

func (v *pathSensitiveInstrOpTemplate) DoDebugRef(*ssa.DebugRef)                       { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoUnOp(*ssa.UnOp)                               { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoBinOp(*ssa.BinOp)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoCall(*ssa.Call)                               { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoChangeInterface(*ssa.ChangeInterface)         { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoChangeType(*ssa.ChangeType)                   { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoConvert(*ssa.Convert)                         { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoSliceArrayToPointer(*ssa.SliceToArrayPointer) { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMakeInterface(*ssa.MakeInterface)             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoExtract(*ssa.Extract)                         { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoSlice(*ssa.Slice)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoReturn(*ssa.Return)                           { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoRunDefers(*ssa.RunDefers)                     { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoPanic(*ssa.Panic)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoSend(*ssa.Send)                               { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoStore(*ssa.Store)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoIf(*ssa.If)                                   { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoJump(*ssa.Jump)                               { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoDefer(*ssa.Defer)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoGo(*ssa.Go)                                   { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMakeChan(*ssa.MakeChan)                       { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoAlloc(*ssa.Alloc)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMakeSlice(*ssa.MakeSlice)                     { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMakeMap(*ssa.MakeMap)                         { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoRange(*ssa.Range)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoNext(*ssa.Next)                               { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoFieldAddr(*ssa.FieldAddr)                     { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoField(*ssa.Field)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoIndexAddr(*ssa.IndexAddr)                     { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoIndex(*ssa.Index)                             { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoLookup(*ssa.Lookup)                           { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMapUpdate(*ssa.MapUpdate)                     { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoTypeAssert(*ssa.TypeAssert)                   { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoMakeClosure(*ssa.MakeClosure)                 { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoPhi(*ssa.Phi)                                 { panic(nil) }
func (v *pathSensitiveInstrOpTemplate) DoSelect(*ssa.Select)                           { panic(nil) }

// Implement path sensitivity operations - optional if you want a simple traversal

func (v *pathSensitiveInstrOpTemplate) NewPath()                 {}
func (v *pathSensitiveInstrOpTemplate) EndPath()                 {}
func (v *pathSensitiveInstrOpTemplate) NewBlock(*ssa.BasicBlock) {}
