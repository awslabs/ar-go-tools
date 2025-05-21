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

// Package escape provides an escape analysis which computes a representation of which references in the program
// are to objects that are local to the current function and goroutine. This information can be used to recover
// local reasoning even in the face of concurrent goroutine execution. This implementation is inspired
// by:
//
// John Whaley and Martin Rinard. 1999. [Compositional Pointer And Escape Analysis For Java Programs.]
// SIGPLAN Not. 34, 10 (Oct. 1999), 187–206.
//
// [Compositional Pointer And Escape Analysis For Java Programs.]: https://doi.org/10.1145/320385.320400
package escape

import (
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/graphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// NillableDerefType gives the type of the result of dereferencing nilable (pointer-like) types.
// No-op (returns the argument) for all other types.
// The standard Go type system cannot represent the type of some nilable types, such as maps or channels.
// A map type is effectively a pointer to the actual map implementation object, but this implementation
// cannot be manipulated directly in Go, so has no type. This is unlike, e.g. *struct{} and struct{}, where
// the dereference type struct{} is a first-class value. The table is:
//
//	nilable      deref
//	-------      -----
//	T*           T
//	[]T          [-1]T
//	func()       impl func()
//	map          impl map
//	chan         impl chan
//	interface{}  impl interface
//
// Slices are isomorphic to a struct value with three fields: a pointer to an array, and integer length/capacity.
// The deref is therefore an array of the same type, but because the size may be dynamic, we use -1 as the
// size (this matches the ssa package convention). Note that []int is a slice, and [-1]int is an array, with the
// former pointing to the later!
// The deref of these "opaque" types is formed by wrapping them in a `impl`, to make a pseudo-type.
// This is currently not supported, and these types are passed through unchanged.
func NillableDerefType(t types.Type) types.Type {
	return nillableDerefType(t, t)
}

// nillableDerefType is the actual implementation of NillableDerefType, that takes the "pretty"
// version of t as an additional argument. This both helps make printing the types shorter, but also
// prevents spurious unwraps.
func nillableDerefType(t types.Type, pretty types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Pointer:
		return tt.Elem()
	case *types.Named:
		// For a named type, recurse on the underlying type. Preserve pretty, so that if we need
		// to wrap the type, we wrap the original type and not the expansion
		x := tt.Underlying()
		return nillableDerefType(x, pretty)
	case *types.Slice:
		return types.NewArray(tt.Elem(), -1) // arrays of length -1 are of statically undetermined size
	case *types.Chan, *types.Map, *types.Interface:
		return &ImplType{pretty}
	case *types.Signature:
		return &FunctionImplType{pretty, nil}
	default:
		return pretty
	}
}

// FunctionImplType represents the pointee of a function pointer
type FunctionImplType struct {
	tp  types.Type
	fun *ssa.Function // may be nil to represent an unknown closure type
}

func (t *FunctionImplType) String() string {
	if t.fun == nil {
		return fmt.Sprintf("impl of %s", t.tp.String())
	}
	return fmt.Sprintf("closure %s of %s", t.fun.String(), t.tp.String())
}

// Underlying returns the underlying type of the function implementation type
func (t *FunctionImplType) Underlying() types.Type {
	return t
}

// ImplType represents the pointee of a map, channel, or interface
type ImplType struct {
	tp types.Type
}

func (t *ImplType) String() string {
	return fmt.Sprintf("impl of %s", t.tp.String())
}

// Underlying returns the underlying type of the implementation type
func (t *ImplType) Underlying() types.Type {
	return t
}

var _ types.Type = (*FunctionImplType)(nil)
var _ types.Type = (*ImplType)(nil)

// AddressOfType computes what type would point to a given type. It is roughly the inverse of NillableDerefType.
func AddressOfType(t types.Type) types.Type {
	return addressOfType(t, t)
}
func addressOfType(t types.Type, pretty types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Named:
		// For a named type, recurse on the underlying type. Preserve pretty, so that if we need
		// to wrap the type, we wrap the original type and not the expansion
		return addressOfType(tt.Underlying(), pretty)
	case *types.Array:
		return types.NewSlice(tt.Elem())
	case *ImplType:
		return tt.tp
	case *FunctionImplType:
		return tt.tp
	default:
		return types.NewPointer(pretty)
	}
}

// ChannelContentsType gives the type of the contents of a channel. No-op otherwise
func ChannelContentsType(t types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Chan:
		return tt.Elem()
	case *types.Named:
		return ChannelContentsType(tt.Underlying())
	default:
		return tt
	}
}

// IsEscapeTracked returns true if t is a type that must be tracked by the escape
// analysis, because it is either a pointer-like type ("nillables"), or it is a struct
// that may directly contain pointer-like types. Struct types are usually represented by
// pointers to a memory object containing the struct, except when the struct is directly
// an argument or return value from a function.
func IsEscapeTracked(t types.Type) bool {
	_, ok := t.Underlying().(*types.Struct)
	return lang.IsNillableType(t) || ok
}

// getCallees wraps ResolveCallee from the analyzer state, giving an error if it fails or doesn't exist.
func (ea *functionAnalysisState) getCallees(instr ssa.CallInstruction) (map[*ssa.Function]lang.CalleeInfo, error) {
	if ea.prog.state == nil {
		return nil, fmt.Errorf("no analyzer state")
	}
	callees, err := ea.prog.state.ResolveCallee(instr, false)
	if err != nil {
		return nil, fmt.Errorf("analyzer state could not resolve callee %v", err)
	}
	return callees, nil
}

// Location structs that enable generating unique load nodes based on a particular instruction
// and load operation within that instruction, as there can be multiple loads implicit in one
// instruction.
type structAssignLoad struct {
	assign ssa.Instruction
	field  string // for recursive structures, will be a compound field name like `.fmt.buffer.length`
}
type generalizedFieldLoad struct {
	assign ssa.Instruction
	field  string // used for map .keys[*], channel .contents, etc.
}
type selectRecvLoad struct {
	selectInstr ssa.Instruction
	recvIndex   int
}

// abstractTypeLoad is used for loads of an abstract type (interface/function impl). Omits the
// instruction so all such loads share the same operation, which substaintially cuts down on the
// number of nodes at the cost of some precision.
type abstractTypeLoad struct {
	tp string
}

// Constants for pseudo-fields of built-in types
const channelContentsField = "contents"
const mapKeysField = "keys[*]"
const mapValuesField = "values[*]"

// CopyStruct copies the fields of src onto dest, while adding load nodes for nillable types.
// The instr parameter is used to key the load nodes to ensure a finite number are created, and
// also to label the node with a line number/pretty printed type.
// tp is the struct type being copied, and field is the parent fields that have already been copied,
// so that recursive struct types get appropriate structAssignLoad locations.
func (g *EscapeGraph) copyStruct(dest *Node, src *Node, instr ssa.Instruction, field string, originalTp types.Type) {
	var tp *types.Struct
	var isReflectValue = false
	if tpNamed, ok := originalTp.(*types.Named); ok {
		isReflectValue = tpNamed.String() == "reflect.Value"
		if tp, ok = tpNamed.Underlying().(*types.Struct); !ok {
			panic(fmt.Errorf("expected to copy struct type, not %v", originalTp))
		}
	} else if tp, ok = originalTp.(*types.Struct); !ok {
		panic(fmt.Errorf("expected to copy struct type, not %v", originalTp))
	}
	for i := 0; i < tp.NumFields(); i++ {
		fieldName, fieldType := tp.Field(i).Name(), tp.Field(i).Type()
		if lang.IsNillableType(fieldType) || (isReflectValue && fieldType.String() == "unsafe.Pointer") {
			fieldNode := g.FieldSubnode(src, fieldName, fieldType)
			g.EnsureLoadNode(structAssignLoad{instr, field + "." + fieldName}, NillableDerefType(fieldType), fieldNode)
			g.WeakAssign(g.FieldSubnode(dest, fieldName, fieldType), fieldNode)
		} else if IsEscapeTracked(fieldType) {
			g.copyStruct(g.FieldSubnode(dest, fieldName, fieldType), g.FieldSubnode(src, fieldName, fieldType), instr, field+"."+fieldName, fieldType)
		}
	}
}

func assertGraphInvariants(g *EscapeGraph) {
	if err := wellFormedEscapeGraph(g); err != nil {
		panic(err)
	}
}

// transferFunction() computes an instruction's effect on a escape graph.
// Modifies g and nodes in place with the effects of the instruction.
// "Transfer function" is interpreted as in the monotone framework.
//
//gocyclo:ignore
func (ea *functionAnalysisState) transferFunction(instruction ssa.Instruction, g *EscapeGraph, callsites map[ssa.CallInstruction]escapeCallsiteInfoImpl) {
	// Switch on the instruction to handle each kind of instructions.
	// Some instructions have sub-kinds depending on their arguments, or have alternate comma-ok forms.
	// If an instruction is handled, return. Otherwise, fall through to the end of the function to print
	// a warning about an unhandled instruction. When the set of instructions is complete, this should turn
	// into an error/panic.
	nodes := ea.nodes
	switch instr := instruction.(type) {
	case *ssa.Alloc:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), EdgeInternal)
		return
	case *ssa.MakeClosure:
		fn := instr.Fn.(*ssa.Function)
		tp := &FunctionImplType{instr.Type(), fn}
		closureNode := nodes.AllocNode(instr, tp)
		nodes.globalNodes.function[closureNode] = fn
		g.AddEdge(nodes.ValueNode(instr), closureNode, EdgeInternal)
		for i, bindingVal := range instr.Bindings {
			if IsEscapeTracked(bindingVal.Type()) {
				g.StoreField(nodes.ValueNode(instr), nodes.ValueNode(bindingVal), fn.FreeVars[i].Name(), fn.FreeVars[i].Type())
			}
		}
		return
	// These three cases look redundant, but instr has a different type in each, which is enough to
	// require separate cases.
	case *ssa.MakeMap:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), EdgeInternal)
		return
	case *ssa.MakeChan:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), EdgeInternal)
		return
	case *ssa.MakeSlice:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), EdgeInternal)
		return
	case *ssa.FieldAddr:
		field := instr.X.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct).Field(instr.Field)
		for varPointee := range g.Pointees(nodes.ValueNode(instr.X)) {
			fieldNode := g.FieldSubnode(varPointee, field.Name(), field.Type())
			g.AddEdge(nodes.ValueNode(instr), fieldNode, EdgeInternal)
		}
		return
	case *ssa.Field:
		if IsEscapeTracked(instr.Type()) {
			field := instr.X.Type().Underlying().(*types.Struct).Field(instr.Field)
			g.WeakAssign(nodes.ValueNode(instr), g.FieldSubnode(nodes.ValueNode(instr.X), field.Name(), field.Type()))
		}
		return
	case *ssa.IndexAddr:
		// raw array is different than *array and slice
		if _, ok := instr.X.Type().Underlying().(*types.Array); ok {
			// Array case. It is unclear how this is generated, and what the semantics should be in this case.
			panic("IndexAddr of direct array")
		} else {
			// *array or slice
			for varPointee := range g.Pointees(nodes.ValueNode(instr.X)) {
				g.AddEdge(nodes.ValueNode(instr), varPointee, EdgeInternal)
			}
			return
		}
	case *ssa.Store:
		if lang.IsNillableType(instr.Val.Type()) {
			g.StoreField(nodes.ValueNode(instr.Addr), nodes.ValueNode(instr.Val), "", nil)
		} else if IsEscapeTracked(instr.Val.Type()) {
			if _, ok := instr.Val.Type().Underlying().(*types.Struct); !ok {
				panic("Store of non-nilable, non-struct type not supported")
			}
			src := nodes.ValueNode(instr.Val)
			for x := range g.Pointees(nodes.ValueNode(instr.Addr)) {
				g.copyStruct(x, src, instr, "", instr.Val.Type())
			}
		}
		return
	case *ssa.UnOp:
		// Check if this is a load operation
		if _, ok := instr.X.Type().(*types.Pointer); ok && instr.Op == token.MUL {
			if lang.IsNillableType(instr.Type()) {
				g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), instr, "", NillableDerefType(instr.Type()))
			} else if IsEscapeTracked(instr.Type()) {
				// Load of struct. Use copy struct to get the fields correctly handled
				for x := range g.Pointees(nodes.ValueNode(instr.X)) {
					g.copyStruct(nodes.ValueNode(instr), x, instr, "", instr.Type())
				}
			}
			return
		} else if _, ok := instr.X.Type().(*types.Chan); ok && instr.Op == token.ARROW {
			// recv on channel
			if lang.IsNillableType(instr.Type()) {
				contentsType := ChannelContentsType(instr.X.Type())
				loadOp := generalizedFieldLoad{instr, channelContentsField}
				g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), loadOp, channelContentsField, contentsType)
			} else if IsEscapeTracked(instr.Type()) {
				for x := range g.Pointees(nodes.ValueNode(instr.X)) {
					g.copyStruct(nodes.ValueNode(instr), x, instr, channelContentsField, instr.Type())
				}
			}
			return
		} else {
			// arithmetic UnOp: no-op
			return
		}
	case *ssa.Send:
		if lang.IsNillableType(instr.X.Type()) {
			// Send on channel
			contentsType := ChannelContentsType(instr.Chan.Type())
			g.StoreField(nodes.ValueNode(instr.Chan), nodes.ValueNode(instr.X), channelContentsField, contentsType)
		} else if IsEscapeTracked(instr.X.Type()) {
			contentsType := ChannelContentsType(instr.Chan.Type())
			for x := range g.Pointees(nodes.ValueNode(instr.Chan)) {
				g.copyStruct(x, nodes.ValueNode(instr.X), instr, channelContentsField, contentsType)
			}
		}
		return
	case *ssa.Slice:
		switch tp := instr.X.Type().Underlying().(type) {
		case *types.Slice:
			// Slice of slice, basic copy
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
			return
		case *types.Basic:
			if tp.Kind() != types.String && tp.Kind() != types.UntypedString {
				panic("Slice of BasicKind that isn't string: " + tp.String())
			}
			// Slice of a string creates a hidden allocation of an array to hold the string contents.
			g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, tp), EdgeInternal)
			return
		case *types.Pointer:
			if _, ok := tp.Elem().Underlying().(*types.Array); !ok {
				panic("Slice of pointer to non-array?")
			}
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
			return
		}
	case *ssa.Return:
		return
	case *ssa.Jump:
		return
	case *ssa.If:
		return
	case *ssa.Select:
		// The result tuple is (index, recvOk, ...recvs), so we need to start the index at 2 and
		// only count receives when assigning indices.
		recvIndex := 2
		for _, st := range instr.States {
			if st.Dir == types.RecvOnly {
				if IsEscapeTracked(ChannelContentsType(st.Chan.Type())) {
					contentsType := ChannelContentsType(st.Chan.Type())
					tupleNode := nodes.ValueNode(instr)
					dest := g.FieldSubnode(tupleNode, fmt.Sprintf("#%d", recvIndex), contentsType)
					loadOp := selectRecvLoad{instr, recvIndex}
					g.LoadField(dest, nodes.ValueNode(st.Chan), loadOp, channelContentsField, contentsType)
				}
				recvIndex++
			} else if st.Dir == types.SendOnly {
				if IsEscapeTracked(st.Send.Type()) {
					// Send on channel is a write to the contents "field" of the channel
					g.StoreField(nodes.ValueNode(st.Chan), nodes.ValueNode(st.Send), channelContentsField, st.Send.Type())
				}
			} else {
				panic("Unexpected select send/recv type")
			}
		}
		return
	case *ssa.Panic:
		g.CallUnknown([]*Node{nodes.ValueNode(instr.X)}, []*Node{}, "panic")
		return
	case *ssa.Call:
		if callsites != nil {
			// We need to copy g because it is about to be clobbered by the transfer function
			callsites[instr] = escapeCallsiteInfoImpl{g.Clone(), instr, ea.nodes, ea.prog}
		}
		// Build the argument array, consisting of the nodes that are the concrete arguments
		// Nil nodes are used for things that aren't pointer-like, so that they line up with
		// the formal parameter definitions.
		args := make([]*Node, len(instr.Call.Args))
		for i, arg := range instr.Call.Args {
			if IsEscapeTracked(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		// For now, we just have one return value that is the merged representation of all of
		// them. For proper tuple-sensitive results, we would need to make this match the real
		// number of return values, and find out which extract operations we should assign the
		// results to.
		rets := []*Node{}
		nReturns := instr.Call.Signature().Results().Len()
		returnNode := nodes.ValueNode(instr)
		if nReturns > 1 {
			for i := 0; i < nReturns; i++ {
				rets = append(rets, g.FieldSubnode(returnNode, fmt.Sprintf("#%d", i), instr.Call.Signature().Results().At(i).Type()))
			}
		} else {
			rets = append(rets, nodes.ValueNode(instr))
		}

		if builtin, ok := instr.Call.Value.(*ssa.Builtin); ok {
			err := transferCallBuiltin(g, instr, builtin, args, rets)
			if err != nil {
				ea.prog.logger.Warnf("Warning, escape analysis does not handle builtin: %s", err)
			}
		} else if callee := instr.Call.StaticCallee(); callee != nil {
			ea.transferCallStaticCallee(instr, g, args, rets)
		} else if instr.Call.IsInvoke() {
			// If no static callee, either we have an indirect call, e.g. t3(t4) or a method invocation,
			// e.g. invoke t3.Method(t8, t13).
			assertGraphInvariants(g)
			ea.transferCallInvoke(instr, g, args, rets)
			if err := wellFormedEscapeGraph(g); err != nil {
				panic(err)
			}
		} else {
			//  Indirect call callees can be closures, bound methods, regular named functions, or thunks.
			ea.transferCallIndirect(instr, g, args, rets)
		}

		return

	case *ssa.Go:
		if callsites != nil {
			callsites[instr] = escapeCallsiteInfoImpl{g.Clone(), instr, ea.nodes, ea.prog}
		}
		// A go call always leaks arguments and receiver/closure. The return value is irrelevant.
		args := make([]*Node, len(instr.Call.Args))
		for i, arg := range instr.Call.Args {
			if IsEscapeTracked(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		// Add the receiver of the call or the closure, if present. The parameters are out
		// of order, but it doesn't matter for CallUnknown.
		switch instr.Call.Value.(type) {
		case *ssa.Function, *ssa.Builtin, *ssa.Global:
			// do nothing, there is no receiver or globals are already leaked
		case ssa.Instruction, *ssa.Parameter, *ssa.FreeVar:
			args = append(args, nodes.ValueNode(instr.Call.Value))
		default:
			panic(fmt.Sprintf("Go statment of unknown value type %s", reflect.TypeOf(instr.Call.Value.String())))
		}
		g.CallUnknown(args, []*Node{}, fmt.Sprintf("go at %v", instr.Parent().Prog.Fset.Position(instr.Pos())))
		return
	case *ssa.Defer:
		// Defer itself is a noop because the actual call occurs during a RunDefers
		return
	case *ssa.RunDefers:
		stacks := ea.deferResults.RunDeferSets[instr]
		finalState := NewEmptyEscapeGraph(ea.nodes)
		initialState := g
		for _, stack := range stacks {
			st := initialState.Clone()
			for _, indices := range stack {
				ins := ea.function.Blocks[indices.Block].Instrs[indices.Ins]
				deferIns, ok := ins.(*ssa.Defer)
				if !ok {
					panic("Defer results referred to non-defer instruction")
				}
				// execute call

				// record callsite context
				if callsites != nil {
					if context, ok := callsites[deferIns]; ok {
						context.g.Merge(st)
					} else {
						callsites[deferIns] = escapeCallsiteInfoImpl{st.Clone(), deferIns, ea.nodes, ea.prog}
					}
				}
				// Build the argument array, consisting of the nodes that are the concrete arguments
				// Nil nodes are used for things that aren't pointer-like, so that they line up with
				// the formal parameter definitions.
				args := make([]*Node, len(deferIns.Call.Args))
				for i, arg := range deferIns.Call.Args {
					if IsEscapeTracked(arg.Type()) {
						args[i] = nodes.ValueNode(arg)
					}
				}
				// For now, we just have one return value that is the merged representation of all of
				// them. For proper tuple-sensitive results, we would need to make this match the real
				// number of return values, and find out which extract operations we should assign the
				// results to.
				rets := []*Node{}
				nReturns := deferIns.Call.Signature().Results().Len()
				returnNode := nodes.UnusedNode()
				if nReturns > 1 {
					for i := 0; i < nReturns; i++ {
						rets = append(rets, st.FieldSubnode(returnNode, fmt.Sprintf("#%d", i), deferIns.Call.Signature().Results().At(i).Type()))
					}
				} else {
					rets = append(rets, nodes.UnusedNode())
				}

				if builtin, ok := deferIns.Call.Value.(*ssa.Builtin); ok {
					err := transferCallBuiltin(st, deferIns, builtin, args, rets)
					if err != nil {
						ea.prog.logger.Warnf("Warning, escape analysis does not handle builtin: %s", err)
					}
				} else if callee := deferIns.Call.StaticCallee(); callee != nil {
					ea.transferCallStaticCallee(deferIns, st, args, rets)
				} else if deferIns.Call.IsInvoke() {
					// If no static callee, either we have an indirect call, e.g. t3(t4) or a method invocation,
					// e.g. invoke t3.Method(t8, t13).
					assertGraphInvariants(st)
					ea.transferCallInvoke(deferIns, st, args, rets)
					if err := wellFormedEscapeGraph(st); err != nil {
						panic(err)
					}
				} else {
					//  Indirect call callees can be closures, bound methods, regular named functions, or thunks.
					ea.transferCallIndirect(deferIns, st, args, rets)
				}
			}
			finalState.Merge(st)
		}
		g.ReplaceBy(finalState)
		return
	case *ssa.Index:
		switch tp := instr.X.Type().Underlying().(type) {
		case *types.Basic:
			if tp.Kind() == types.String || tp.Kind() == types.UntypedString {
				// string index is no-op
				return
			}
		case *types.Slice:
			g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), instr, "", nil)
			return
		case *types.Array:
			if IsEscapeTracked(instr.Type()) {
				g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
			}
			return
		}
	case *ssa.Lookup:
		if IsEscapeTracked(instr.Type()) {
			g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), instr, mapValuesField, instr.Type())
		}
		return
	case *ssa.MapUpdate:
		if IsEscapeTracked(instr.Value.Type()) {
			g.StoreField(nodes.ValueNode(instr.Map), nodes.ValueNode(instr.Value), mapValuesField, instr.Value.Type())
		}
		if IsEscapeTracked(instr.Key.Type()) {
			g.StoreField(nodes.ValueNode(instr.Map), nodes.ValueNode(instr.Key), mapKeysField, instr.Key.Type())
		}
		return
	case *ssa.Next:
		if !instr.IsString {
			tupleNode := nodes.ValueNode(instr)
			// The result is (ok, key, value), so we put keys in #1 and values in #2, and ignore the bool in #0
			keyType := instr.Type().Underlying().(*types.Tuple).At(1).Type()
			valueType := instr.Type().Underlying().(*types.Tuple).At(2).Type()
			if IsEscapeTracked(keyType) {
				loadOp := generalizedFieldLoad{instr, mapKeysField}
				g.LoadField(g.FieldSubnode(tupleNode, "#1", keyType), nodes.ValueNode(instr.Iter), loadOp, mapKeysField, keyType)
			}
			if IsEscapeTracked(valueType) {
				loadOp := generalizedFieldLoad{instr, mapValuesField}
				g.LoadField(g.FieldSubnode(tupleNode, "#2", valueType), nodes.ValueNode(instr.Iter), loadOp, mapValuesField, valueType)
			}
		}
		return
	case *ssa.Range:
		if _, ok := instr.X.Type().Underlying().(*types.Map); ok {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		} else {
			// range over string, not interesting to escape
			return
		}
		return
	case *ssa.MakeInterface:
		if lang.IsNillableType(instr.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		} else if IsEscapeTracked(instr.X.Type()) {
			// Making a struct into an interface means creating a new allocation to hold the value,
			// copying the struct over, and then pointing the interface at the allocation
			allocNode := nodes.AllocNode(instr, instr.X.Type())
			g.WeakAssign(allocNode, nodes.ValueNode(instr.X))
			g.AddEdge(nodes.ValueNode(instr), allocNode, EdgeInternal)
		} else {
			g.AddNode(nodes.ValueNode(instr)) // Make interface from int, string or other non-pointer type
		}
		return
	case *ssa.TypeAssert:
		dest := nodes.ValueNode(instr)
		if instr.CommaOk {
			dest = g.FieldSubnode(dest, "#0", instr.AssertedType)
		}
		if IsEscapeTracked(instr.AssertedType) {
			src := nodes.ValueNode(instr.X)
			for e := range g.Pointees(src) {
				// propogate untyped nodes or nodes that have a type that matches. We use
				// AddressOfType, because if the node has type e.g. struct or impl of map, we need
				// to allow assignment to asserted types *struct or map.
				if tp, ok := g.nodes.globalNodes.types[e]; !ok || types.AssignableTo(AddressOfType(tp), instr.AssertedType) {
					g.AddEdge(dest, e, EdgeInternal)
				}
			}
		}
		// TODO: do we need an alternative case for type-asserts directly to a struct type?
		return
	case *ssa.Convert:
		if IsEscapeTracked(instr.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		} else if _, ok := instr.Type().Underlying().(*types.Slice); ok {
			if basic, ok := instr.X.Type().Underlying().(*types.Basic); ok &&
				(basic.Kind() == types.String || basic.Kind() == types.UntypedString) {
				// We must be converting a string to a slice, so the semantics are to do a hidden allocation
				g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), EdgeInternal)
			}
		}
		return
	case *ssa.ChangeInterface:
		g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		return
	case *ssa.ChangeType:
		if IsEscapeTracked(instr.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		}
		return
	case *ssa.SliceToArrayPointer:
		g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		return
	case *ssa.Phi:
		if IsEscapeTracked(instr.Type()) {
			for _, v := range instr.Edges {
				g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(v))
			}
		}
		return
	case *ssa.Extract:
		if _, ok := instr.Tuple.(*ssa.Phi); ok {
			panic("Extract from phi?")
		}
		if IsEscapeTracked(instr.Type()) {
			src := nodes.ValueNode(instr.Tuple)
			dest := nodes.ValueNode(instr)
			g.WeakAssign(dest, g.FieldSubnode(src, fmt.Sprintf("#%d", instr.Index), instr.Type()))
		}
		return
	case *ssa.BinOp:
		return
	case *ssa.DebugRef:
		// Noop, as debugref is just an annotation for mapping back to source
		return
	default:
	}
	if ea.prog.logger.LogsDebug() {
		pos := instruction.Parent().Prog.Fset.Position(instruction.Pos())
		ea.prog.logger.Debugf("Unhandled: (type: %s) %v at %v\n",
			formatutil.SanitizeRepr(reflect.TypeOf(instruction)),
			formatutil.SanitizeRepr(instruction), pos)
	}
}

func (ea *functionAnalysisState) transferCallStaticCallee(instrType ssa.CallInstruction, g *EscapeGraph, args []*Node, rets []*Node) {
	// Handle calls where we know the callee
	callee := instrType.Common().StaticCallee()
	summary := ea.prog.getFunctionAnalysisSummary(callee)
	if summary.HasSummaryGraph() {
		// We can use the finalGraph pointer freely as it will never change after it is created
		summary.RecordUse(summaryUse{ea, instrType})
		if ea.prog.logger.LogsTrace() {
			ea.prog.logger.Tracef("Call at %v: %v %v %v\n", instrType.Parent().Prog.Fset.Position(instrType.Pos()),
				summary.function.String(), args, summary.finalGraph.nodes.formals)
		}
		freeVars := []*Node{}
		// For a immediately invoked func, the  value will be a MakeClosure, where we can get the
		// freevars directly from. In this case, we don't need field sensitivity to align the right
		// value, as we can directly get the corresponding node.
		if mkClosure, ok := instrType.Common().Value.(*ssa.MakeClosure); ok {
			for _, fv := range mkClosure.Bindings {
				freeVars = append(freeVars, ea.nodes.ValueNode(fv))
			}
		}
		g.Call(g.Clone(), nil, args, freeVars, rets, summary.finalGraph)
	} else if summary.summaryType == "reflect:ValueOf" {
		unsafePtrTp := summary.function.Signature.Results().At(0).Type().Underlying().(*types.Struct).Field(1).Type()
		g.WeakAssign(g.FieldSubnode(rets[0], "ptr", unsafePtrTp), args[0])
	} else if summary.summaryType == "reflect:(Value).Interface" {
		g.WeakAssign(rets[0], g.FieldSubnode(args[0], "ptr", nil))
	} else if summary.summaryType == "reflect:JsonMarshal" {
		ea.jsonMarshal(instrType, g, args, rets)
	} else if summary.summaryType == "reflect:JsonUnmarshal" {
		ea.jsonUnmarshal(instrType, g, args, rets)
	} else {
		// If we didn't find a summary or didn't know the callee, use the arbitrary function assumption.
		// Crucially, this is different from a function that will have a summary but we just haven't
		// seen yet (e.g. when there is recursion). If we haven't seen a function, then it will have the
		// initial lattice value (basically, the empty graph), and as the monotone framework loop proceeds,
		// will get more and more edges. This case, by contrast, imposes a fixed semantics: leak all the
		// arguments and return an object which may be arbitrary (and is therefore leaked).
		if ea.prog.logger.LogsDebug() {
			ea.prog.logger.Debugf("Possible precision loss, %v is not a summarized function: treating as unknown call\n",
				callee.String())
		}
		g.CallUnknown(args, rets, callee.String())
	}
}

// jsonMarshal implements the effect of a marshalling operation. This is essentially to call the
// MarshalJSON method on all the reachable types from the argument node.
func (ea *functionAnalysisState) jsonMarshal(instrType ssa.CallInstruction, g *EscapeGraph, args []*Node, rets []*Node) {
	prog := instrType.Parent().Pkg.Prog
	marshalerInterface := lang.FindTypeByName(prog, "encoding/json", "Marshaler")
	if marshalerInterface == nil {
		ea.prog.logger.Errorf("Found function with reflect:JsonMarshal escape summary, but program does not import encoding/json")
		return
	}
	reachable := map[*Node]bool{}
	worklist := []*Node{args[0]}
	for len(worklist) > 0 {
		node := worklist[0]
		worklist = worklist[:len(worklist)-1]
		for n := range g.Pointees(node) {
			if !reachable[n] {
				reachable[n] = true
				worklist = append(worklist, n)
			}
		}
	}
	for receiverNode := range reachable {
		if tp, ok := g.nodes.globalNodes.types[receiverNode]; ok {
			if _, ok := tp.(*ImplType); ok {
				continue
			}
			marshalJsonMethod, _ := lang.FindImplementationMethod(prog, tp, marshalerInterface, "MarshalJSON")
			if marshalJsonMethod != nil {
				ea.invokeMethodDirectly(instrType, g, marshalJsonMethod, receiverNode, []*Node{}, rets)
			}
		}
	}
}

// jsonUnmarshal computes the effect of calling json.Unmarshal(_, x). This considers the types of
// the pointees and computes which other types are reachable from those fields. It also handles the
// case of unmarshaling into the "any" type, which causes the marshalling code to generate some
// fixed types (map[string]any, []any, string, float64, etc.).
func (ea *functionAnalysisState) jsonUnmarshal(instrType ssa.CallInstruction, g *EscapeGraph, args []*Node, rets []*Node) {
	prog := instrType.Parent().Pkg.Prog
	marshalerInterface := lang.FindTypeByName(prog, "encoding/json", "Unmarshaler")
	if marshalerInterface == nil {
		ea.prog.logger.Errorf("Found function with reflect:JsonUnmarshal escape summary, but program does not import encoding/json")
		return
	}
	// Find some fixed types for strings, map[string]any, and []any
	stringTp := types.Universe.Lookup("string").Type()
	var mapStringAnyTp = types.NewMap(stringTp, types.NewInterfaceType([]*types.Func{}, []types.Type{}))
	var sliceAnyTp = types.NewSlice(types.NewInterfaceType([]*types.Func{}, []types.Type{}))

	// Fill will fill the fields of a struct or other object as necessary. Alloc creates new nodes,
	// caching the results to ensure we create a cyclic structure instead of creating infinite nodes.
	var fill func(n *Node, tp types.Type)
	var alloc func(tp types.Type) *Node
	fresh := map[*Node]bool{}

	alloc = func(tp types.Type) *Node {
		node := g.nodes.IndexedAllocNode(instrType, tp.String(), tp)
		if !fresh[node] {
			fresh[node] = true
			fill(node, tp)
		}
		return node
	}

	fill = func(n *Node, tp types.Type) {
		if lang.IsAnyType(tp) {
			// handle `any`, which gets filled with maps, slices, and individual allocations
			g.AddEdge(n, alloc(NillableDerefType(mapStringAnyTp)), EdgeInternal)
			g.AddEdge(n, alloc(sliceAnyTp), EdgeInternal)
			g.AddEdge(n, alloc(stringTp), EdgeInternal)
		} else if impl, ok := tp.(*ImplType); ok {
			// Handle the implict values[*] field on map implementation nodes
			if mapTp, ok := impl.tp.Underlying().(*types.Map); ok {
				fill(g.FieldSubnode(n, mapValuesField, mapTp.Elem()), mapTp.Elem())
			}
		} else if array, ok := tp.Underlying().(*types.Array); ok {
			// Arrays (including the pointee of slices) are filled at the same node, which is
			// required because they don't have a "contents" psuedo-field like maps do.
			fill(n, array.Elem())
		} else if lang.IsNillableType(tp) {
			// nillable types get a new node for their type
			g.AddEdge(n, alloc(NillableDerefType(tp)), EdgeInternal)
		} else if IsEscapeTracked(tp) {
			// handle struct typed nodes
			unmarshalJsonMethod, _ := lang.FindImplementationMethod(prog, tp, marshalerInterface, "UnmarshalJSON")
			if unmarshalJsonMethod != nil {
				// Handle custom unmarshaling methods
				ea.invokeMethodDirectly(instrType, g, unmarshalJsonMethod, n, []*Node{args[0]}, rets)
			} else {
				structType := tp.Underlying().(*types.Struct)
				// Handle structs default
				for i := 0; i < structType.NumFields(); i++ {
					field := structType.Field(i)
					if field.Exported() && IsEscapeTracked(field.Type()) {
						// the field needs to be handled
						subnode := g.FieldSubnode(n, field.Name(), field.Type())
						fill(subnode, field.Type())
					}
				}
			}
		}
	}

	// Go through the arguments of UnmarshalJSON and fill in their fields. These objects are not
	// allocated, only filled
	for p := range g.Pointees(args[1]) {
		if tp, ok := g.nodes.globalNodes.types[p]; ok {
			fill(p, tp)
		}
	}

}

// invokeMethodDirectly is a helper method that applies the specific method identified in callee
// with the given receiver node. This is useful for the json(Un)marshal methods as they need to
// invoke the effects of custom marshal/unmarshaling functions (UnmarshalJSON, etc).s
func (ea *functionAnalysisState) invokeMethodDirectly(instr ssa.CallInstruction, g *EscapeGraph, callee *ssa.Function, receiver *Node, args []*Node, rets []*Node) {
	summary := ea.prog.getFunctionAnalysisSummary(callee)
	if summary.HasSummaryGraph() {
		// Record our use of this summary for recursion-covergence purposes
		summary.RecordUse(summaryUse{ea, instr})
		if lang.IsNillableType(callee.Params[0].Type()) {
			// Add indirection for pointer types
			tmp := g.nodes.NewNode(KindVar, "tmp", types.NewPointer(callee.Params[0].Type()))
			g.AddEdge(tmp, receiver, EdgeInternal)
			pre := g.Clone()
			g.Call(pre, tmp, append([]*Node{tmp}, args...), nil, rets, summary.finalGraph)
		} else if IsEscapeTracked(callee.Params[0].Type()) {
			pre := g.Clone()
			// The receiver has struct type, so use receiver node directly
			g.Call(pre, receiver, append([]*Node{receiver}, args...), nil, rets, summary.finalGraph)
		} else {
			pre := g.Clone()
			// The receiver has primitive type, so use a nil receiver
			g.Call(pre, nil, append([]*Node{nil}, args...), nil, rets, summary.finalGraph)
		}
	} else {
		g.CallUnknown(append([]*Node{receiver}, args...), rets, callee.String())
	}
}

type closureFreeVarLoad struct {
	instr ssa.Instruction
	field string
}

//gocyclo:ignore
func (ea *functionAnalysisState) transferCallIndirect(instrType ssa.CallInstruction, g *EscapeGraph, args []*Node, rets []*Node) {
	// Handle indirect calls. The approach is the same for both indirect and invoke:
	// Loop through all the different out-edges of the func value/receiver. If they are local, we
	// know which MakeClosure/concrete type was used to create that node, so process the ssa.Function.
	// If there are any out-edges to an non-local value (either leaked or escaped), then use the pointer
	// analysis to over-approximate the set of possiblities, and then call each of those.
	pre := g.Clone()
	calleeNode := ea.nodes.ValueNode(instrType.Common().Value)
	nonlocal := g.status[calleeNode] != Local
	for closureNode := range g.Pointees(calleeNode) {
		// The closure node represents the actual closure object.
		// Its fields point at allocs which hold the actual data. If the actual
		// data is a pointer to struct/interface, then the alloc will just hold a pointer
		// calleeNode --> closureNode --> new *S --> struct S
		if g.status[closureNode] == Local {
			// Find the corresponding ssa.Function, and perform the invoke
			if concreteCallee, ok := ea.nodes.globalNodes.function[closureNode]; ok {
				summary := ea.prog.getFunctionAnalysisSummary(concreteCallee)
				if summary.HasSummaryGraph() {
					// Record our use of this summary for recursion-covergence purposes
					summary.RecordUse(summaryUse{ea, instrType})

					// Free vars should be a list of the possible alloc nodes that
					// hold each free var.
					freeVars := []*Node{}
					for _, fv := range concreteCallee.FreeVars {
						if IsEscapeTracked(fv.Type()) {
							varFieldNode := pre.FieldSubnode(closureNode, fv.Name(), fv.Type())

							freeVars = append(freeVars, varFieldNode)
						} else {
							freeVars = append(freeVars, nil)
						}
					}
					g.Call(pre, nil, args, freeVars, rets, summary.finalGraph)
				} else {
					g.CallUnknown(args, rets, concreteCallee.String())
				}
				if err := wellFormedEscapeGraph(g); err != nil {
					panic(err)
				}
			}
		} else {
			nonlocal = true
		}
	}
	if nonlocal {
		// Either the pointer or a closure object was non-local. Therefore we can't know for certain exactly what function was called
		// or what data the closure refers to. Therefore, we need to basically do all the logic again, but assuming arbitrary
		// data could be loaded from e.g. free vars.
		if callees, err := ea.getCallees(instrType); err == nil {
			pre := g.Clone()
			for concreteCallee := range callees {
				summary := ea.prog.getFunctionAnalysisSummary(concreteCallee)
				if summary.HasSummaryGraph() {
					// Record our use of this summary for recursion-covergence purposes
					summary.RecordUse(summaryUse{ea, instrType})

					for closureNode := range g.Pointees(calleeNode) {
						if tp, ok := g.nodes.globalNodes.types[closureNode]; ok {
							if IsAbstractType(tp) {
								closureNode = g.ImplementationSubnode(closureNode, &FunctionImplType{concreteCallee.Signature, concreteCallee})
							} else if funcImpl, ok := tp.(*FunctionImplType); ok && funcImpl.fun != concreteCallee {
								continue // the closure node is not our concrete callee
							}
						}

						if err := wellFormedEscapeGraph(g); err != nil {
							panic(err)
						}
						// Check if the closure node itself is non-local (i.e. escaped if it is an argument) and the callee
						// is a closure. In this case, we need to make sure there is at least one node representing the free
						// variables of the closure. Failure to create this node will result in the function essentially
						// assuming the free variables are nil, as there won't be any closure out edges.
						if g.status[closureNode] != Local {
							// Add a load node for external closures, to represent the bound variable storage nodes
							freeVars := []*Node{}
							for _, fv := range concreteCallee.FreeVars {
								if IsEscapeTracked(fv.Type()) {
									varFieldNode := pre.FieldSubnode(closureNode, fv.Name(), fv.Type())
									loadOp := closureFreeVarLoad{instrType, fv.Name()}
									g.EnsureLoadNode(loadOp, NillableDerefType(concreteCallee.FreeVars[0].Type()), varFieldNode)
									pre.EnsureLoadNode(loadOp, NillableDerefType(concreteCallee.FreeVars[0].Type()), varFieldNode)
									freeVars = append(freeVars, varFieldNode)
								} else {
									freeVars = append(freeVars, nil)
								}
							}
							v := pre.Clone()
							v.Call(pre, nil, args, freeVars, rets, summary.finalGraph)
							g.Merge(v)
						}
						if err := wellFormedEscapeGraph(g); err != nil {
							panic(err)
						}
					}
				} else {
					g.CallUnknown(args, rets, concreteCallee.String())
				}
			}
		} else {
			ea.prog.logger.Debugf("Warning, can't resolve indirect of %v, treating as unknown call\n", instrType)
			g.CallUnknown(args, rets, fmt.Sprintf("unknown callee at %v", instrType.Parent().Prog.Fset.Position(instrType.Pos())))
		}
	}
	if ea.prog.logger.LogsTrace() {
		ea.prog.logger.Tracef("After indirect call:\n%v", g.Graphviz())
	}
}

func (ea *functionAnalysisState) transferCallInvoke(instrType ssa.CallInstruction, g *EscapeGraph, args []*Node, rets []*Node) {
	// Find the methods that it could be, according to pointer analysis
	// Invoke each with each possible receiver
	// Note: unlike for indirect calls, we do the full cross product of all possible method implementations
	// with all receivers, even ones that we could deduce aren't possible.
	receiverNode := ea.nodes.ValueNode(instrType.Common().Value)
	if callees, err := ea.getCallees(instrType); err == nil {
		pre := g.Clone()
		for callee := range callees {
			summary := ea.prog.getFunctionAnalysisSummary(callee)
			if summary.HasSummaryGraph() {
				// Record our use of this summary for recursion-covergence purposes
				summary.RecordUse(summaryUse{ea, instrType})
				if lang.IsNillableType(callee.Params[0].Type()) {
					// The receiver has pointer type, so we're good
					g.Call(pre, receiverNode, append([]*Node{receiverNode}, args...), nil, rets, summary.finalGraph)
				} else if IsEscapeTracked(callee.Params[0].Type()) {
					// The receiver has struct type, so deref the indirect receiver explicitly
					for x := range pre.Pointees(receiverNode) {
						g.Call(pre, x, append([]*Node{x}, args...), nil, rets, summary.finalGraph)
					}
				} else {
					// The receiver has primitive type, so use a nil receiver
					g.Call(pre, nil, append([]*Node{nil}, args...), nil, rets, summary.finalGraph)
				}
			} else {
				g.CallUnknown(append([]*Node{receiverNode}, args...), rets, callee.String())
			}
		}
	} else {
		ea.prog.logger.Debugf("Warning, %v invoke did not find callees, treating as unknown call (err: %v)\n", instrType, err)
		callString := fmt.Sprintf("uknown callee at %v", instrType.Parent().Prog.Fset.Position(instrType.Pos()))
		g.CallUnknown(append([]*Node{receiverNode}, args...), rets, callString)
	}
	if ea.prog.logger.LogsTrace() {
		ea.prog.logger.Tracef("After invoke call:\n%v", g.Graphviz())
	}
}

// transferCallBuiltin computes the result of calling an builtin. The name (len, copy, etc) and the
// effective type can be retrieved from the ssa.Builtin. An unknown function has no bound on its
// allow semantics. This means that the arguments are assumed to leak, and the return value is
// treated similarly to a load node, except it can never be resolved with arguments like loads can
// be.
//
//gocyclo:ignore
func transferCallBuiltin(g *EscapeGraph, instr ssa.Instruction, builtin *ssa.Builtin, args []*Node, rets []*Node) error {
	switch builtin.Name() {
	case "len": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "cap": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "close": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "complex": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "real": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "imag": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "print": // No-op, as does not leak and no return value
		return nil
	case "println": // No-op, as does not leak and no return value
		return nil
	case "recover": // We don't track panic values, so treat like an unknown call
		g.CallUnknown(args, rets, "recover")
		return nil
	case "ssa:wrapnilchk": // treat as identity fucntion
		g.WeakAssign(rets[0], args[0])
		return nil
	case "delete": // treat as noop, as we don't actually erase information
		return nil
	case "append":
		// handle code like `ret = append(slice, x)`
		// slice is a slice, and so is x.
		// Basically, we copy all the outedges from *x to *slice
		// Then we copy all the edges from *slice to a new allocation node, which
		// represents the case where there wasn't enough space (we don't track enough
		// information to distinguish these possibilities ourselves.)
		if len(args) != 2 {
			panic("Append must have exactly 2 args")
		}
		sliceArg, xArg, ret := args[0], args[1], rets[0]
		sig := builtin.Type().(*types.Signature)
		sliceType := sig.Results().At(0).Type().Underlying().(*types.Slice)
		// First, simulate the write to the array
		for baseArray := range g.Pointees(sliceArg) {
			for xArray := range g.Pointees(xArg) {
				g.WeakAssign(baseArray, xArray)
			}
			// The return value can be one of the existing backing arrays
			g.AddEdge(ret, baseArray, EdgeInternal)
		}
		// Then, simulate an allocation. This happens second so we pick up the newly added edges
		allocArray := g.nodes.AllocNode(instr, types.NewArray(sliceType.Elem(), -1))
		for baseArray := range g.Pointees(sliceArg) {
			g.WeakAssign(allocArray, baseArray) // TODO: use a field representing the contents?
		}
		g.AddEdge(ret, allocArray, EdgeInternal)
		return nil
	case "copy":
		// copy(dest, src)
		// Both arguments are slices: copy all the outedges from *src to *dest
		// Ignore the return value
		// Special case: src is a string. Do nothing in that case, as we don't track
		// characters. This is handled by not having any edges from a nil srcArg.
		if len(args) != 2 {
			panic("Copy must have exactly 2 args")
		}
		destArg, srcArg := args[0], args[1]
		// Simulate the write to the array
		for destArray := range g.Pointees(destArg) {
			for srcArray := range g.Pointees(srcArg) {
				g.WeakAssign(destArray, srcArray)
			}
		}
		return nil
	case "String": // converts something to a string, which isn't tracked
		return nil
	case "SliceData", "Slice": // Both convert a slice to/from its underlying array
		g.WeakAssign(rets[0], args[0])
		return nil
	case "StringData", "Add":
		return fmt.Errorf("unsafe operation %v", builtin.Name())
	default:
		return fmt.Errorf("unhandled: %v", builtin.Name())
	}
}

type functionAnalysisState struct {
	function     *ssa.Function
	prog         *ProgramAnalysisState
	deferResults *defers.Results
	initialGraph *EscapeGraph                     // the graph on entry to the function. never mutated.
	nodes        *NodeGroup                       // the nodes used in these graphs
	blockEnd     map[*ssa.BasicBlock]*EscapeGraph // the monotone framework result at each basic block end
	// mutability: the finalGraph will never be mutated in place, so saving a reference without Clone() is safe
	finalGraph *EscapeGraph

	// persist the worklist so we can add basic blocks of function calls that changep
	worklist []*ssa.BasicBlock

	// records uses of this summary in other functions, used to trigger re-analysis
	summaryUses map[summaryUse]*EscapeGraph

	// Gives the type of the summary ("unknown", "summarize", "noop", specific hardcoded summary, etc)
	summaryType string

	overflow          bool
	reportedTypeError bool
}

// Used to record the position at which a function summary graph is used.
// The function here is a *functionAnalysisState rather than ssa.Function
// (or even just ssa.Instruction) to support context-sensitivity.
type summaryUse struct {
	function    *functionAnalysisState
	instruction ssa.Instruction
}

type parameterLoad struct {
	function *ssa.Function
	param    int
}

// Adds nodes for global objects (both package vars and address-taken static functions) that are
// referenced explicitly by the body of f. Nodes for things not referenced may be added from the
// summaries of other functions, but these don't need special handling.
func addGlobalObjectNodes(f *ssa.Function, initialGraph *EscapeGraph) {
	operands := []*ssa.Value{}
	for _, blk := range f.Blocks {
		for _, instr := range blk.Instrs {
			operands = operands[:0]
			// Avoid picking up the static callee of function calls
			if c, ok := instr.(*ssa.Call); ok && c.Call.StaticCallee() != nil {
				for i := range c.Call.Args {
					operands = append(operands, &c.Call.Args[i])
				}
			} else if _, ok := instr.(*ssa.DebugRef); ok {
				// do nothing to ignore debugref
			} else {
				operands = instr.Operands(operands)
			}
			for _, v := range operands {
				switch vv := (*v).(type) {
				case *ssa.Global:
					initialGraph.AddEdge(initialGraph.nodes.ValueNode(vv), initialGraph.nodes.globalNodes.GlobalNode(vv), EdgeExternal)
				case *ssa.Function:
					initialGraph.AddEdge(initialGraph.nodes.ValueNode(vv), initialGraph.nodes.globalNodes.StaticFunctionNode(vv), EdgeExternal)
				}
			}
		}
	}

}

// newFunctionAnalysisState creates a new function analysis for the given function, tied to the given whole program analysis
func newFunctionAnalysisState(f *ssa.Function, prog *ProgramAnalysisState, summaryType string) (ea *functionAnalysisState) {
	nodes := NewNodeGroup(prog.globalNodes)
	initialGraph := NewEmptyEscapeGraph(nodes)
	for i, p := range f.Params {
		var formalNode *Node = nil
		if lang.IsNillableType(p.Type()) {
			paramNode := nodes.ParamNode(p)
			formalNode = nodes.ValueNode(p)
			initialGraph.AddEdge(formalNode, paramNode, EdgeInternal)
			// Add a "load" operation to the pointee of parameters. These nodes are not exactly load
			// nodes, but we need to treat them as such for the purposes of EnsureLoadNode. We use a
			// parameter load operation if it is a normal type, and an abstractTypeLoad if it is
			// abstract. Normally this distinction is handled by EnsureLoadNode, but we aren't
			// creating true load nodes here so we must do it ourselves.
			pointeeType := NillableDerefType(p.Type())
			if !IsAbstractType(pointeeType) {
				initialGraph.nodes.loadOps[paramNode] = map[any]bool{parameterLoad{f, i}: true}
			} else {
				loadOp := abstractTypeLoad{pointeeType.String()}
				initialGraph.nodes.loadOps[paramNode] = map[any]bool{loadOp: true}
			}
		} else if IsEscapeTracked(p.Type()) {
			formalNode = nodes.ValueNode(p)
			initialGraph.AddNode(formalNode)
			initialGraph.MergeNodeStatus(formalNode, Escaped, nil)
		}
		nodes.formals = append(nodes.formals, formalNode)
	}
	for i, p := range f.FreeVars {
		var freeVarNode *Node = nil
		if lang.IsNillableType(p.Type()) {
			paramNode := nodes.ParamNode(p)
			freeVarNode = nodes.ValueNode(p)
			initialGraph.AddEdge(freeVarNode, paramNode, EdgeInternal)
			// Do the same pseudo-load node logic as for parameters in the above loop
			pointeeType := NillableDerefType(p.Type())
			if !IsAbstractType(pointeeType) {
				initialGraph.nodes.loadOps[paramNode] = map[any]bool{parameterLoad{f, len(f.Params) + i}: true}
			} else {
				loadOp := abstractTypeLoad{pointeeType.String()}
				initialGraph.nodes.loadOps[paramNode] = map[any]bool{loadOp: true}
			}
		} else if IsEscapeTracked(p.Type()) {
			freeVarNode = nodes.ValueNode(p)
			initialGraph.AddNode(freeVarNode)
			initialGraph.MergeNodeStatus(freeVarNode, Escaped, nil)
		}
		nodes.freevars = append(nodes.freevars, freeVarNode)
	}
	addGlobalObjectNodes(f, initialGraph)

	worklist := []*ssa.BasicBlock{}
	if len(f.Blocks) > 0 {
		worklist = append(worklist, f.Blocks[0])
	}
	defersResults := defers.AnalyzeFunction(f, prog.logger)
	return &functionAnalysisState{
		f,
		prog,
		&defersResults,
		initialGraph,
		nodes,
		make(map[*ssa.BasicBlock]*EscapeGraph),
		NewEmptyEscapeGraph(nodes),
		worklist,
		map[summaryUse]*EscapeGraph{},
		summaryType,
		false,
		false,
	}
}

// Monotonicity checking is extremely expensive, and is only useful as a manual debugging
// tool while developing the escape analysis.
type cachedGraphMonotonicity struct {
	input  *EscapeGraph
	output *EscapeGraph
}

var instructionMonoCheckData map[ssa.Instruction][]cachedGraphMonotonicity = map[ssa.Instruction][]cachedGraphMonotonicity{}
var checkMonotonicityEveryInstruction = false

func (ea *functionAnalysisState) HasSummaryGraph() bool {
	return ea != nil && (ea.summaryType == config.EscapeBehaviorSummarize && !ea.overflow) || ea.summaryType == config.EscapeBehaviorNoop
}

func (ea *functionAnalysisState) RecordUse(useLocation summaryUse) {
	ea.summaryUses[useLocation] = ea.finalGraph
}

// ProcessBlock performs the monotone transfer function for a particular block, and returns
// whether the end graph changed. This function computes the merge of the predecessors,
// iterates over each instruction, and then stores the result (if different) into
// the blockEnd map.
func (ea *functionAnalysisState) ProcessBlock(bb *ssa.BasicBlock) (changed bool) {
	g := NewEmptyEscapeGraph(ea.nodes)
	if len(bb.Preds) == 0 {
		// Entry block uses the function-wide initial graph
		g.Merge(ea.initialGraph)
	} else {
		// Take the union of all our predecessors. Treat nil as no-ops; they will
		// be filled in later, and then the current block will be re-analyzed
		for _, pred := range bb.Preds {
			if predGraph := ea.blockEnd[pred]; predGraph != nil {
				g.Merge(predGraph)
			}
		}
	}
	for _, instr := range bb.Instrs {
		// Check the monotonicity of the transfer function.
		if checkMonotonicityEveryInstruction {
			pre := g.Clone()
			ea.transferFunction(instr, g, nil)
			post := g.Clone()
			if pairs, ok := instructionMonoCheckData[instr]; ok {
				for _, p := range pairs {
					// Directly check all pairs for monotonicity
					if less, _ := p.input.LessEqual(pre); less {
						if lessOut, reason := p.output.LessEqual(post); !lessOut {
							ea.prog.logger.Warnf("Monotonicity violation at %v because %s\n", instr, reason)
							ea.prog.logger.Warnf("A <= B but !(C <= D)\nA (old pre):\n%v\nB (new pre):\n%v\nC (old post):\n%v\nD (new post):\n%v\n",
								p.input.Graphviz(),
								pre.Graphviz(),
								p.output.Graphviz(),
								post.Graphviz())
						}
					}
				}
			}
			instructionMonoCheckData[instr] = append(instructionMonoCheckData[instr], cachedGraphMonotonicity{pre, post})
		} else {
			ea.transferFunction(instr, g, nil)
		}
	}
	if oldGraph, ok := ea.blockEnd[bb]; ok {
		if oldGraph.Matches(g) {
			return false
		}
	}
	ea.blockEnd[bb] = g
	return true
}

// addToBlockWorklist adds the block to the function's worklist, if it is not already present.
// After this call returns, block will definitely be on the worklist.
func (ea *functionAnalysisState) addToBlockWorklist(block *ssa.BasicBlock) {
	found := false
	for _, entry := range ea.worklist {
		if entry == block {
			found = true
		}
	}
	if !found {
		ea.worklist = append(ea.worklist, block)
	}
}

func graphTooLarge(state *dataflow.State, g *EscapeGraph) bool {
	if state == nil || g == nil {
		return false
	}
	if len(g.Edges(nil, nil, EdgeAll)) > state.Config.EscapeConfig.SummaryMaximumSize {
		return true
	}
	return false
}

// RunForwardIterative is an implementation of the convergence loop of the monotonic framework.
// Each block is processed, and if it's result changes the successors are added.
func (ea *functionAnalysisState) RunForwardIterative() error {
	if len(ea.function.Blocks) == 0 {
		return nil
	}
	for len(ea.worklist) > 0 {
		block := ea.worklist[0]
		ea.worklist = ea.worklist[1:]
		g := ea.blockEnd[block]
		if graphTooLarge(ea.prog.state, g) {
			stats := ""
			counts := map[string]int{}
			for n := range g.status {
				counts[n.debugInfo]++
			}
			items := []struct {
				s string
				c int
			}{}
			for s, c := range counts {
				items = append(items, struct {
					s string
					c int
				}{s, c})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].c > items[j].c })
			for _, s := range items {
				stats += fmt.Sprintf("; %d - %s", s.c, s.s)
			}
			return fmt.Errorf("intermediate graph too large: %s", stats)
		}
		if ea.ProcessBlock(block) {
			for _, nextBlock := range block.Succs {
				ea.addToBlockWorklist(nextBlock)
			}
		}
	}
	return nil
}

// EscapeSummary computes the escape summary for a single function, independently of all other functions.
// Other functions are treated as arbitrary.
func EscapeSummary(f *ssa.Function) (graph *EscapeGraph) {
	prog := &ProgramAnalysisState{
		make(map[*ssa.Function]*functionAnalysisState),
		newGlobalNodeGroup(),
		config.NewLogGroup(config.NewDefault()),
		nil,
		false,
	}
	analysis := newFunctionAnalysisState(f, prog, config.EscapeBehaviorSummarize)
	analysis.Resummarize()
	return analysis.finalGraph
}

// ProgramAnalysisState contains the summaries for the entire program. Currently, this is just a simple
// wrapper around a map of function to analysis results, but it will likely need to expand
// to work with the taint analysis.
type ProgramAnalysisState struct {
	summaries     map[*ssa.Function]*functionAnalysisState
	globalNodes   *globalNodeGroup
	logger        *config.LogGroup
	state         *dataflow.State
	builtWorklist bool
}

// getSummaryType returns the kind of summary that f should have under the given configuration. This
// takes into account function and package level directives.
func getSummaryType(ec *config.EscapeConfig, f *ssa.Function) string {
	functionStatus, ok := ec.Functions[f.String()]
	if ok {
		return functionStatus
	}
	pkg := lang.PackageTypeFromFunction(f)
	if pkg == nil || ec.MatchPkgFilter(pkg.Path()) {
		return config.EscapeBehaviorSummarize
	}
	return config.EscapeBehaviorUnknown
}

// getFunctionAnalysisSummary gets or creates a summary for the given function, and returns it. The
// summary is configured according to the EscapeConfig in the state that was used to build this
// ProgramAnalysisState. Functions that must be summarized may only be correctly handled if they are
// discovered during initialization; if they are discovered later because e.g. they aren't part of
// the initial callgraph, then they must be set to "unknown"
func (prog *ProgramAnalysisState) getFunctionAnalysisSummary(f *ssa.Function) *functionAnalysisState {
	if r, ok := prog.summaries[f]; ok {
		return r
	}
	state := newFunctionAnalysisState(f, prog, getSummaryType(prog.state.Config.EscapeConfig, f))
	prog.summaries[f] = state
	// This function has requested summary, but is added after the worklist is built. This would
	// result in a soundness issue.
	if prog.builtWorklist && state.summaryType == config.EscapeBehaviorSummarize {
		prog.logger.Warnf("Asking to summarize %q after worklist creation; only fixed summaries supported for such functions\n", f.String())
		state.summaryType = config.EscapeBehaviorUnknown
	}
	return state
}

// (Re)-compute the escape summary for a single function. This will re-run the analysis
// monotone framework loop and update the finalGraph. Returns true if the finalGraph
// changed from its prior version.
func (ea *functionAnalysisState) Resummarize() (changed bool) {
	if ea.summaryType != config.EscapeBehaviorSummarize {
		return false
	}

	err := ea.RunForwardIterative()
	returnResult := NewEmptyEscapeGraph(ea.nodes)
	// Use an empty summary (else branch) if we get an error from the convergence loop
	if err == nil {
		for block, blockEndState := range ea.blockEnd {
			if len(block.Instrs) > 0 {
				if retInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
					returnResult.Merge(blockEndState)
					for i, rValue := range retInstr.Results {
						if IsEscapeTracked(rValue.Type()) {
							returnResult.WeakAssign(ea.nodes.ReturnNode(i, rValue.Type()), ea.nodes.ValueNode(rValue))
						}
					}
				}
			}
		}
	} else {
		if ea.overflow {
			return false
		}
		ea.prog.logger.Warnf("Warning, could not compute summary for %s: %v\n", ea.function.String(), err)
		ea.overflow = true
		return true
	}

	// Trim all the nodes unreachable from the external visible ones (params, returns, and globals)
	roots := []*Node{}
	roots = append(roots, returnResult.nodes.formals...)
	roots = append(roots, returnResult.nodes.freevars...)
	for _, x := range returnResult.nodes.returnNodes {
		roots = append(roots, x)
	}
	returnResult = returnResult.CloneReachable(roots)
	simplifySummary(returnResult)
	if wellFormedErr := wellFormedEscapeGraph(returnResult); wellFormedErr != nil {
		panic(wellFormedErr)
	}
	if graphTooLarge(ea.prog.state, returnResult) {
		if ea.overflow {
			return false
		}
		ea.prog.logger.Warnf("Warning, could not compute summary for %s: %v\n", ea.function.String(), err)
		ea.overflow = true
		return true
	}
	same := ea.finalGraph != nil && ea.finalGraph.Matches(returnResult)
	// The returnResult is always a fresh graph rather than mutating the old one, so we preserve the invariant
	// that the finalGraph never mutates
	ea.finalGraph = returnResult
	return !same
}

// EscapeAnalysis computes the bottom-up escape summaries of functions matching the package filter.
//
//gocyclo:ignore
func EscapeAnalysis(state *dataflow.State, root *callgraph.Node) (*ProgramAnalysisState, error) {
	prog := &ProgramAnalysisState{
		summaries:   make(map[*ssa.Function]*functionAnalysisState),
		globalNodes: newGlobalNodeGroup(),
		logger:      state.Logger,
		state:       state,
	}

	// Find all the nodes that are in the main package, and thus treat everything else as not summarized
	nodes := []*callgraph.Node{}
	nodesToAnalyze := map[*ssa.Function]bool{}
	for f, node := range state.PointerAnalysis.CallGraph.Nodes {
		state := prog.getFunctionAnalysisSummary(f)
		if state.summaryType == config.EscapeBehaviorSummarize {
			nodes = append(nodes, node)
			nodesToAnalyze[f] = true
		}
	}
	// Mark the worklist as complete. If there are any other functions added after this point, they
	// won't be analyzed soundly.
	prog.builtWorklist = true

	if prog.logger.LogsTrace() {
		prog.logger.Tracef("Have a total of %d nodes", len(nodes))
	}
	succ := func(n *callgraph.Node) []*callgraph.Node {
		succs := []*callgraph.Node{}
		for _, e := range n.Out {
			succs = append(succs, e.Callee)
		}
		return succs
	}

	// Build the worklist in reverse topological order, so that summaries are computed
	// before the functions that use them. This relies on the worklist being pulled
	// from at the end. We need to work from the append side so that when we are
	// processing an SCC, the functions are re-analyzed before moving on to the next
	// SCC. If we tracked the worklist by SCC, we could make this even more efficient
	// by putting the node not at top of the stack but at the bottom of the current
	// SCC so that other members of the SCC are analyzed first.
	// (We first build the worklist in normal order, then reverse it, as prepending to a slice is
	// not efficient.)
	worklist := make([]*functionAnalysisState, 0)
	sccOfFunc := map[*functionAnalysisState]int{}
	for sccIndex, scc := range graphutil.StronglyConnectedComponents(nodes, succ) {
		for _, n := range scc {
			if summary, ok := prog.summaries[n.Func]; ok && nodesToAnalyze[n.Func] {
				sccOfFunc[summary] = sccIndex
				worklist = append(worklist, summary)
			}
		}
	}
	// Reverse the worklist
	for i, j := 0, len(worklist)-1; i < j; i, j = i+1, j-1 {
		worklist[i], worklist[j] = worklist[j], worklist[i]
	}
	// The main worklist algorithm. Reanalyze each function, putting any function(s) that need to be reanalyzed back on
	// the list
	for len(worklist) > 0 {
		summary := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		prog.logger.Debugf("Computing escape summary for %s (%d to go)\n", formatutil.SanitizeRepr(summary.function), len(worklist))
		changed := summary.Resummarize()
		if !changed {
			continue
		}
		// Iterate over the places where this summary is used, and schedule them to be re-analyzed
		for location, graphUsed := range summary.summaryUses {
			if !summary.finalGraph.Matches(graphUsed) {
				location.function.addToBlockWorklist(location.instruction.Block())
				// Add to the worklist if it isn't already there
				found := false
				for _, entry := range worklist {
					if entry == location.function {
						found = true
						break
					}
				}
				if !found {
					worklist = append(worklist, location.function)
					i := len(worklist) - 1
					for i > 0 && sccOfFunc[worklist[i]] == sccOfFunc[worklist[i-1]] {
						worklist[i], worklist[i-1] = worklist[i-1], worklist[i]
						i = i - 1
					}
				}
			}
		}
	}
	// Print out the final graphs for debugging purposes
	if prog.logger.LogsTrace() {
		for f := range state.PointerAnalysis.CallGraph.Nodes {
			summary := prog.summaries[f]
			if summary != nil && summary.nodes != nil && f.Pkg != nil {
				if strings.HasSuffix(f.String(), ").Error") {
					state.Logger.Tracef("Final summary (size %d) for %s is:%s\n", len(summary.finalGraph.status), formatutil.Sanitize(f.String()), summary.finalGraph.Graphviz())
				}
			}
		}
	}
	return prog, nil
}

// derefsAreLocal returns nil if all of the nodes pointed to by `ptr` are local, i.e.
// not escaped or leaked. Ignores the status of `ptr` itself. Otherwise, returns a non-nil rationale
// for why a pointee is non-local
func derefsAreLocal(g *EscapeGraph, ptr *Node) *dataflow.EscapeRationale {
	for n := range g.Pointees(ptr) {
		g.AddNode(n) // Ensure n's status is correct for .IntrinsicStatus nodes() (e.g. globals)
		if g.status[n] != Local {
			if rat, ok := g.rationales[n]; ok && rat != nil {
				return rat
			}
			if g.status[n] == Leaked {
				return dataflow.NewBaseRationale("missing rationale")
			}
			return dataflow.NewBaseRationale("escaped but not leaked")
		}
	}
	return nil
}

// instructionLocality returns nil if the given instruction is local w.r.t. the given escape graph.
// Otherwise, it returns a non-nil EscapeRationale.
//
//gocyclo:ignore
func instructionLocality(instr ssa.Instruction, g *EscapeGraph) *dataflow.EscapeRationale {
	switch instrType := instr.(type) {
	case *ssa.Store:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Addr))
	case *ssa.UnOp:
		if _, ok := instrType.X.Type().(*types.Pointer); ok && instrType.Op == token.MUL {
			// Load Op
			return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
		} else if _, ok := instrType.X.Type().(*types.Chan); ok && instrType.Op == token.ARROW {
			// recv on channel
			return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
		}
		// arithmetic is local
		return nil
	case *ssa.Send:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Chan))
	case *ssa.Range:
		if _, ok := instrType.X.Type().Underlying().(*types.Map); ok {
			return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
		}
		// must be a string type
		return nil
	case *ssa.Next:
		if instrType.IsString {
			return nil
		}
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Iter))
	case *ssa.Select:
		for _, state := range instrType.States {
			chanRationale := derefsAreLocal(g, g.nodes.ValueNode(state.Chan))
			if chanRationale != nil {
				return chanRationale
			}
		}
		return nil
	case *ssa.BinOp:
		return nil // arithmetic is local
	case *ssa.Go:
		return nil // go func is clearly non-local
	case *ssa.Call:
		return nil // functions require special handling
	case *ssa.MakeClosure:
		// Making a closure is a local operation. The resulting closure may close over external
		// objects, or may itself leak immediately, but the creation is semantically equivalent
		// to writing some fields in a hidden struct type
		return nil
	case *ssa.Defer, *ssa.RunDefers:
		// Defers and rundefers are local, as they in principle just access the stack of defered funcs.
		// Execution of the defered closures, or the process of creating the closures, may be non-local
		// but those are handled elsewhere
		return nil
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeChan, *ssa.MakeSlice:
		// All alloc-like operations are local
		return nil
	case *ssa.FieldAddr, *ssa.IndexAddr:
		// address calculations don't involve loads
		// TODO: what about ssa.IndexAddr with arrays?
		return nil
	case *ssa.Field, *ssa.Index:
		// Field/Index is always applied to a value type, so it does not access memory.
		return nil
	case *ssa.Slice, *ssa.SliceToArrayPointer:
		return nil // taking sub-slices is an array operation
	case *ssa.MakeInterface, *ssa.Convert,
		*ssa.ChangeInterface, *ssa.ChangeType, *ssa.Phi, *ssa.Extract:
		// conversions and ssa specific things don't access memory
		return nil
	case *ssa.TypeAssert:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
	case *ssa.Return, *ssa.Jump, *ssa.If:
		// control flow (at least the operation itself, if not the computation of the argument(s)) is local
		return nil
	case *ssa.Panic:
		// Panicing does not itself leak, although it may of course trigger executions that are non-local
		return nil
	case *ssa.MapUpdate:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Map))
	case *ssa.Lookup:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
	default:
		// fallthrough to the unhandled case below.
		// Some operation can fallthrough as well, because they might not (yet) handle all forms of their instruction type.
	}
	return dataflow.NewBaseRationale("instruction locality unknown")
}

// basicBlockInstructionLocality fills in the locality map with the locality information
// of the instructions in the given basic block.
func basicBlockInstructionLocality(ea *functionAnalysisState, bb *ssa.BasicBlock,
	locality map[ssa.Instruction]*dataflow.EscapeRationale, callsites map[ssa.CallInstruction]escapeCallsiteInfoImpl) error {
	g := NewEmptyEscapeGraph(ea.nodes)
	if len(bb.Preds) == 0 {
		// Entry block uses the function-wide initial graph
		g.Merge(ea.initialGraph)
	} else {
		// Take the union of all our predecessors. Treat nil as no-ops; they will
		// be filled in later, and then the current block will be re-analyzed
		for _, pred := range bb.Preds {
			if predGraph := ea.blockEnd[pred]; predGraph != nil {
				g.Merge(predGraph)
			}
		}
	}
	for _, instr := range bb.Instrs {
		locality[instr] = instructionLocality(instr, g)
		ea.transferFunction(instr, g, callsites)
	}
	return nil
}

type escapeCallsiteInfoImpl struct {
	g        *EscapeGraph
	callsite ssa.CallInstruction
	nodes    *NodeGroup
	prog     *ProgramAnalysisState
}

// computeInstructionLocality does the work of computing instruction locality for a function. See
// wrapper `ComputeInstructionLocality` for details.
func computeInstructionLocality(ea *functionAnalysisState, initial *EscapeGraph) (locality map[ssa.Instruction]*dataflow.EscapeRationale, callsiteInfo map[ssa.CallInstruction]escapeCallsiteInfoImpl) {
	deferResults := defers.AnalyzeFunction(ea.function, ea.prog.logger)
	inContextEA := &functionAnalysisState{
		function:     ea.function,
		deferResults: &deferResults,
		prog:         ea.prog,
		initialGraph: initial,
		nodes:        ea.nodes,
		blockEnd:     make(map[*ssa.BasicBlock]*EscapeGraph),
		worklist:     []*ssa.BasicBlock{ea.function.Blocks[0]},
		summaryType:  config.EscapeBehaviorSummarize,
	}
	inContextEA.Resummarize()
	locality = map[ssa.Instruction]*dataflow.EscapeRationale{}
	callsites := map[ssa.CallInstruction]escapeCallsiteInfoImpl{}
	for _, block := range ea.function.Blocks {
		basicBlockInstructionLocality(inContextEA, block, locality, callsites)
	}
	if ea.prog.logger.LogsTrace() {
		ea.prog.logger.Tracef("Final graph after computing locality for %s is\n%s\n", ea.function.Name(), inContextEA.finalGraph.Graphviz())
	}
	return locality, callsites
}

// CanPointTo determines whether a escape graph node labeled with type a can have
// a type-correct outedge to a node with type b. The result is conservative in the
// sense that it defaults to true in the cases where the type system doesn't give
// enough information, or the types don't yet have a typechecking rule.
func CanPointTo(a, b types.Type) bool {
	switch a := a.(type) {
	case *types.Pointer:
		pointeeType := NillableDerefType(a)
		if types.AssignableTo(b.Underlying(), pointeeType.Underlying()) {
			return true
		}
		if arrayType, ok := b.Underlying().(*types.Array); ok {
			// We allow *T to point to [n]T, or [n][m]T, etc.
			// recursion is bounded because `b` is always .Elem()'d
			if CanPointTo(a, arrayType.Elem()) {
				return true
			}
		}
		return false
	}

	return true
}

// TypecheckEscapeGraph determines whether its argument is type-correct. If a problem is found, a
// non-nil error is returned describing the problem. This function is advisory only; it will be
// unsound when the program uses e.g. unsafe constructs, and incomplete in that it will not check
// all possible ill-typed constructs. It is instead intended to aid debugging by isolating type
// errors to the place(s) where they are first introduced.
//
//gocyclo:ignore
func TypecheckEscapeGraph(g *EscapeGraph) error {
	typesMap := g.nodes.globalNodes.types
	for n, succs := range g.edges {
		if _, ok := g.status[n]; !ok {
			return fmt.Errorf("Node %v has no status", n)
		}
		for s := range succs {
			if _, ok := g.status[s]; !ok {
				return fmt.Errorf("Node %v (reachable from %v) has no status", s, n)
			}
		}
	}
	for n := range g.status {
		if _, ok := g.edges[n]; !ok {
			return fmt.Errorf("Node %v has no edges", n)
		}
		tpN := typesMap[n]
		if tpN == nil {
			continue
		}
		if tpN.String() == "invalid type" {
			return fmt.Errorf("can't have node with invalid type %v:%v", n, tpN)
		}
		realType := tpN.Underlying()
		if n.kind == KindGlobal && !g.IsSubnode(n) {
			realType = NillableDerefType(realType)
		}
		switch tp := realType.(type) {
		case *types.Pointer:
			for _, e := range g.Edges(n, nil, EdgeExternal|EdgeInternal) {
				destType := typesMap[e.dest]
				if destType == nil {
					continue
				}
				if e.dest.kind == KindGlobal && !g.IsSubnode(e.dest) {
					destType = NillableDerefType(destType)
				}
				if !CanPointTo(tp, destType) {
					return fmt.Errorf("can't have edge between %v:%v --> %v:%v", n, tpN, e.dest, destType)
				}
			}
		case *types.Struct:
			// TODO: check fields
		}
	}
	return nil
}

// wellFormedEscapeGraph checks some basic consistency invariants for an escape graph
func wellFormedEscapeGraph(g *EscapeGraph) error {
	for n, succs := range g.edges {
		if n == nil {
			return fmt.Errorf("Node is nil")
		}
		if _, ok := g.status[n]; !ok {
			return fmt.Errorf("Node %v has no status", n)
		}
		for s := range succs {
			if _, ok := g.status[s]; !ok {
				return fmt.Errorf("Node %v (reachable from %v) has no status", s, n)
			}
		}
	}
	for n := range g.status {
		if _, ok := g.edges[n]; !ok {
			return fmt.Errorf("Node %v has no edges", n)
		}
	}
	return nil
}

// simplifySummary removes irrelevant load nodes from a given function summary graph. "Irrelevant"
// nodes are load nodes that don't have any leaks or incoming/outgoing internal edges (and also
// doesn't point to any nodes that need to be kept). Modifies g in-place.
func simplifySummary(g *EscapeGraph) {
	// The set of nodes to be removed
	candidatesForRemoval := map[*Node]struct{}{}
	// Find all load nodes that are escaped and not leaked, without any outgoing internal edges
	for node, status := range g.status {
		statusAllowsRemoval := status == Escaped || (status == Leaked && g.IsSubnode(node))
		if node.kind == KindLoad && statusAllowsRemoval && len(g.Edges(node, nil, EdgeInternal)) == 0 {
			candidatesForRemoval[node] = struct{}{}
		}
	}
	// Filter nodes with incoming internal edges. The candidates now only have external/subnode
	// edges.
	for src, outEdges := range g.edges {
		for dest, flags := range outEdges {
			if flags&EdgeInternal != 0 {
				delete(candidatesForRemoval, dest)
			}
			if flags&EdgeSubnode != 0 && g.status[src] != g.status[dest] {
				delete(candidatesForRemoval, dest)
			}
		}
	}
	// Make sure nodes that point to non-candidates aren't removed
	removeNodesReachingNonCandidate(g, candidatesForRemoval)
	// Finally, remove the selected nodes from g
	removeNodesInSet(g, candidatesForRemoval)
}

// removeNodesReachingNonCandidate removes nodes from the candidate set that transitively reach, via
// edges, a node not a candidate for removal. This effectively runs a convergence loop where if a
// node points at something that isn't a candidate, it is not a candidate either. This could
// potentially be more efficient if we had a map of back-edges, but this depends on the depth we
// need to propogate non-candidacy backwards and the cost of creating such a back-edge map. Modifies
// candidatesForRemove in-place.
func removeNodesReachingNonCandidate(g *EscapeGraph, candidatesForRemoval map[*Node]struct{}) {
	for {
		changed := false
		for src := range candidatesForRemoval {
			for dest := range g.edges[src] {
				if _, ok := candidatesForRemoval[dest]; !ok {
					if _, ok := candidatesForRemoval[src]; ok {
						delete(candidatesForRemoval, src)
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}
}

// removeNodesInSet removes nodes from g indicated by candidatesForRemoval. Modifies g in-place.
func removeNodesInSet(g *EscapeGraph, candidatesForRemoval map[*Node]struct{}) {
	for x := range candidatesForRemoval {
		delete(g.status, x)
		delete(g.edges, x)
	}
	// Also remove edges that point at these nodes, which may come from nodes that aren't being removed.
	for _, outEdges := range g.edges {
		for c := range candidatesForRemoval {
			delete(outEdges, c)
		}
	}
	// Remove internal out-edges from leaked nodes. There is no reason to track information about
	// leaked objects other than the fact that they are leaked. The leaked status will already have
	// propogated to the target node by the time this happens.
	for x, out := range g.edges {
		if g.status[x] == Leaked {
			for next, status := range out {
				if status == EdgeInternal {
					delete(out, next)
				}
			}
		}
	}
}
