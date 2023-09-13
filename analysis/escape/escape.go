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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
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
//	interface{}  impl interface
//	chan         impl chan
//
// Slices are isomorphic to a struct value with three fields: a pointer to an array, and integer length/capacity.
// The deref is therefore an array of the same type, but because the size may be dynamic, we use -1 as the
// size (this matches the ssa package convention). Note that []int is a slice, and [-1]int is an array, with the
// former pointing to the later!
// The deref of these "opaque" types is formed by wrapping them in a `impl`, to make a pseudo-type.
// This is currently not supported, and these types are passed through unchanged.
func NillableDerefType(t types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Pointer:
		return tt.Elem()
	case *types.Named:
		return NillableDerefType(tt.Underlying())
	case *types.Slice:
		return types.NewArray(tt.Elem(), -1) // arrays of length -1 are of statically undetermined size
	default:
		return tt
	}
}

// ChannelContentsType gives the type of the contents of a channel. No-op otherwise
func ChannelContentsType(t types.Type) types.Type {
	switch tt := t.Underlying().(type) {
	case *types.Chan:
		return tt.Elem()
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
func (ea *functionAnalysisState) getCallees(instr ssa.CallInstruction) (map[*ssa.Function]dataflow.CalleeInfo, error) {
	if ea.prog.state == nil {
		return nil, fmt.Errorf("No analyzer state")
	}
	if callees, err := ea.prog.state.ResolveCallee(instr, false); err != nil {
		return nil, fmt.Errorf("Analyzer state could not resolve callee %v", err)
	} else {
		return callees, nil
	}
}

// Location structs that enable generating unique load nodes based on a particular instruction
// and load operation within that instruction, as there can be multiple loads implicit in one
// instruction.
type structAssignLoad struct {
	assign ssa.Instruction
	field  string // for recursive structures, will be a compound field name like `.fmt.buffer.length`
}
type mapKeyValueLoad struct {
	access ssa.Instruction
	field  string
}
type selectRecvLoad struct {
	selectInstr ssa.Instruction
	recvIndex   int
}

var channelContentsField = "contents"

// CopyStruct copies the fields of src onto dest, while adding load nodes for nillable types.
// The instr parameter is used to key the load nodes to ensure a finite number are created, and
// also to label the node with a line number/pretty printed type.
// tp is the struct type being copied, and field is the parent fields that have already been copied,
// so that recursive struct types get appropriate structAssignLoad locations.
func (g *EscapeGraph) copyStruct(dest *Node, src *Node, instr ssa.Instruction, field string, tp *types.Struct) {
	for i := 0; i < tp.NumFields(); i++ {
		fieldName, fieldType := tp.Field(i).Name(), tp.Field(i).Type()
		if lang.IsNillableType(fieldType) {
			fieldNode := g.FieldSubnode(src, fieldName, fieldType)
			if g.status[fieldNode] != Local {
				g.AddEdge(fieldNode, g.nodes.LoadNode(structAssignLoad{instr, field + "." + fieldName}, instr, NillableDerefType(fieldType)), false)
			}
			g.WeakAssign(g.FieldSubnode(dest, fieldName, fieldType), fieldNode)
		} else if IsEscapeTracked(fieldType) {
			fieldStructType := fieldType.Underlying().(*types.Struct)
			g.copyStruct(g.FieldSubnode(dest, fieldName, fieldType), g.FieldSubnode(src, fieldName, fieldType), instr, field+"."+fieldName, fieldStructType)
		}
	}
}

// transferFunction() computes an instruction's effect on a escape graph.
// Modifies g and nodes in place with the effects of the instruction.
// "Transfer function" is interpreted as in the monotone framework.
//
//gocyclo:ignore
func (ea *functionAnalysisState) transferFunction(instruction ssa.Instruction, g *EscapeGraph, verbose bool) {
	// Switch on the instruction to handle each kind of instructions.
	// Some instructions have sub-kinds depending on their arguments, or have alternate comma-ok forms.
	// If an instruction is handled, return. Otherwise, fall through to the end of the function to print
	// a warning about an unhandled instruction. When the set of instructions is complete, this should turn
	// into an error/panic.
	nodes := ea.nodes
	switch instr := instruction.(type) {
	case *ssa.Alloc:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), true)
		return
	case *ssa.MakeClosure:
		closureNode := nodes.AllocNode(instr, instr.Type())
		fn := instr.Fn.(*ssa.Function)
		nodes.globalNodes.function[closureNode] = fn
		g.AddEdge(nodes.ValueNode(instr), closureNode, true)
		for i, bindingVal := range instr.Bindings {
			g.StoreField(nodes.ValueNode(instr), nodes.ValueNode(bindingVal), fn.FreeVars[i].Name(), fn.FreeVars[i].Type())
		}
		return
	case *ssa.MakeMap:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, instr.Type()), true)
		return
	case *ssa.MakeChan:
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, instr.Type()), true)
		return
	case *ssa.MakeSlice:
		elemType := instr.Type().Underlying().(*types.Slice).Elem()
		g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, types.NewArray(elemType, -1)), true)
		return
	case *ssa.FieldAddr:
		field := instr.X.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct).Field(instr.Field)
		for varPointee := range g.Deref(nodes.ValueNode(instr.X)) {
			fieldNode := g.FieldSubnode(varPointee, field.Name(), field.Type())
			g.AddEdge(nodes.ValueNode(instr), fieldNode, true)
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
			for varPointee := range g.Deref(nodes.ValueNode(instr.X)) {
				g.AddEdge(nodes.ValueNode(instr), varPointee, true)
			}
			return
		}
	case *ssa.Store:
		if lang.IsNillableType(instr.Val.Type()) {
			g.StoreField(nodes.ValueNode(instr.Addr), nodes.ValueNode(instr.Val), "", nil)
		} else if IsEscapeTracked(instr.Val.Type()) {
			t, ok := instr.Val.Type().Underlying().(*types.Struct)
			if !ok {
				panic("Store of non-nilable, non-struct type not supported")
			}
			src := nodes.ValueNode(instr.Val)
			for x := range g.Deref(nodes.ValueNode(instr.Addr)) {
				g.copyStruct(x, src, instr, "", t)
			}
		}
		return
	case *ssa.UnOp:
		// Check if this is a load operation
		if _, ok := instr.X.Type().(*types.Pointer); ok && instr.Op == token.MUL {
			if lang.IsNillableType(instr.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, instr, NillableDerefType(instr.Type().Underlying()))
				}
				g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), gen, "", nil)
			} else if IsEscapeTracked(instr.Type()) {
				// Load of struct. Use copy struct to get the fields correctly handled
				t := instr.Type().Underlying().(*types.Struct)
				for x := range g.Deref(nodes.ValueNode(instr.X)) {
					g.copyStruct(nodes.ValueNode(instr), x, instr, "", t)
				}
			}
			return
		} else if _, ok := instr.X.Type().(*types.Chan); ok && instr.Op == token.ARROW {
			// recv on channel
			if lang.IsNillableType(instr.Type()) {
				contentsType := ChannelContentsType(instr.X.Type().Underlying())
				gen := func() *Node {
					return nodes.LoadNode(instr, instr, NillableDerefType(contentsType))
				}
				g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), gen, channelContentsField, contentsType)
			} else if IsEscapeTracked(instr.Type()) {
				ea.prog.logger.Warnf("Channel of struct %s unhandled", instr.Type().String())
			}
			return
		} else {
			// arithmetic UnOp: no-op
			return
		}
	case *ssa.Send:
		if lang.IsNillableType(instr.X.Type()) {
			// Send on channel
			contentsType := ChannelContentsType(instr.X.Type().Underlying())
			g.StoreField(nodes.ValueNode(instr.Chan), nodes.ValueNode(instr.X), channelContentsField, contentsType)
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
			g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, tp), true)
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
					gen := func() *Node {
						return nodes.LoadNode(selectRecvLoad{instr, recvIndex}, instr, contentsType)
					}
					tupleNode := nodes.ValueNode(instr)
					dest := g.FieldSubnode(tupleNode, fmt.Sprintf("#%d", recvIndex), contentsType)
					g.LoadField(dest, nodes.ValueNode(st.Chan), gen, channelContentsField, contentsType)
				}
				recvIndex += 1
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
		g.CallUnknown([]*Node{nodes.ValueNode(instr.X)}, []*Node{})
		return
	case *ssa.Call:
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
			ea.transferCallStaticCallee(instr, g, verbose, args, rets)
		} else if instr.Call.IsInvoke() {
			// If no static callee, either we have an indirect call, e.g. t3(t4) or a method invocation,
			// e.g. invoke t3.Method(t8, t13).
			ea.transferCallInvoke(instr, g, verbose, args, rets)
		} else {
			//  Indirect call callees can be closures, bound methods, regular named functions, or thunks.
			ea.transferCallIndirect(instr, g, verbose, args, rets)
		}

		return

	case *ssa.Go:
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
		g.CallUnknown(args, []*Node{})
		return
	case *ssa.Defer:

	case *ssa.Index:
		switch tp := instr.X.Type().Underlying().(type) {
		case *types.Basic:
			if tp.Kind() == types.String || tp.Kind() == types.UntypedString {
				// string index is no-op
				return
			}
		case *types.Slice:
			gen := func() *Node {
				return nodes.LoadNode(instr, instr, NillableDerefType(NillableDerefType(instr.X.Type())))
			}
			g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), gen, "", nil)
			return
		case *types.Array:
			if IsEscapeTracked(instr.Type()) {
				g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
			}
			return
		}
	case *ssa.Lookup:
		if IsEscapeTracked(instr.Type().Underlying()) {
			gen := func() *Node { return nodes.LoadNode(instr, instr, instr.Type()) }
			g.LoadField(nodes.ValueNode(instr), nodes.ValueNode(instr.X), gen, "values[*]", instr.Type())
		}
		return
	case *ssa.MapUpdate:
		if IsEscapeTracked(instr.Value.Type()) {
			g.StoreField(nodes.ValueNode(instr.Map), nodes.ValueNode(instr.Value), "values[*]", instr.Value.Type())
		}
		if IsEscapeTracked(instr.Key.Type()) {
			g.StoreField(nodes.ValueNode(instr.Map), nodes.ValueNode(instr.Key), "keys[*]", instr.Key.Type())
		}
		return
	case *ssa.Next:
		if !instr.IsString {
			tupleNode := nodes.ValueNode(instr)
			// The result is (ok, key, value), so we put keys in #1 and values in #2, and ignore the bool in #0
			keyType := instr.Type().Underlying().(*types.Tuple).At(1).Type()
			valueType := instr.Type().Underlying().(*types.Tuple).At(2).Type()
			if IsEscapeTracked(keyType) {
				gen := func() *Node {
					return nodes.LoadNode(mapKeyValueLoad{instr, "keys[*]"}, instr, NillableDerefType(keyType))
				}
				g.LoadField(g.FieldSubnode(tupleNode, "#1", keyType), nodes.ValueNode(instr.Iter), gen, "keys[*]", keyType)
			}
			if IsEscapeTracked(valueType) {
				gen := func() *Node {
					return nodes.LoadNode(mapKeyValueLoad{instr, "values[*]"}, instr, NillableDerefType(valueType))
				}
				g.LoadField(g.FieldSubnode(tupleNode, "#2", valueType), nodes.ValueNode(instr.Iter), gen, "values[*]", valueType)
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
			g.AddEdge(nodes.ValueNode(instr), allocNode, true)
		} else {
			g.AddNode(nodes.ValueNode(instr)) // Make interface from string or other non-pointer type
		}
		return
	case *ssa.TypeAssert:
		if IsEscapeTracked(instr.Type()) {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		}
		return
	case *ssa.Convert:
		if IsEscapeTracked(instr.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instr), nodes.ValueNode(instr.X))
		} else if _, ok := instr.Type().Underlying().(*types.Slice); ok {
			if basic, ok := instr.X.Type().Underlying().(*types.Basic); ok &&
				(basic.Kind() == types.String || basic.Kind() == types.UntypedString) {
				// We must be converting a string to a slice, so the semantics are to do a hidden allocation
				g.AddEdge(nodes.ValueNode(instr), nodes.AllocNode(instr, NillableDerefType(instr.Type())), true)
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
		ea.prog.logger.Debugf("Unhandled: (type: %s) %v at %v\n", reflect.TypeOf(instruction).String(), instruction, pos)
	}
}

func (ea *functionAnalysisState) transferCallStaticCallee(instrType *ssa.Call, g *EscapeGraph, verbose bool, args []*Node, rets []*Node) {
	// Handle calls where we know the callee
	callee := instrType.Call.StaticCallee()
	summary := ea.prog.summaries[callee]
	if summary != nil {
		// We can use the finalGraph pointer freely as it will never change after it is created
		summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph
		if verbose {
			ea.prog.logger.Tracef("Call at %v: %v %v %v\n", instrType.Parent().Prog.Fset.Position(instrType.Pos()),
				summary.function.String(), args, summary.finalGraph.nodes.formals)
		}
		freeVars := [][]*Node{}
		// For a immediately invoked func, the  value will be a MakeClosure, where we can get the
		// freevars directly from. In this case, we don't need field sensitivity to align the right
		// value, as we can directly get the corresponding node.
		if mkClosure, ok := instrType.Call.Value.(*ssa.MakeClosure); ok {
			for _, fv := range mkClosure.Bindings {
				pointees := []*Node{}
				for p := range g.Deref(ea.nodes.ValueNode(fv)) {
					pointees = append(pointees, p)
				}
				freeVars = append(freeVars, pointees)
			}
		}
		g.Call(args, freeVars, rets, summary.finalGraph)
		if verbose {
			ea.prog.logger.Tracef("After call:\n%v", g.Graphviz())
		}
	} else {
		if verbose {
			ea.prog.logger.Tracef("Warning, %v is not a summarized function: treating as unknown call\n",
				callee.Name())
		}
		// If we didn't find a summary or didn't know the callee, use the arbitrary function assumption.
		// Crucially, this is different from a function that will have a summary but we just haven't
		// seen yet (e.g. when there is recursion). If we haven't seen a function, then it will have the
		// initial lattice value (basically, the empty graph), and as the monotone framework loop proceeds,
		// will get more and more edges. This case, by contrast, imposes a fixed semantics: leak all the
		// arguments and return an object which may be arbitrary (and is therefore leaked).
		g.CallUnknown(args, rets)
	}
}

type closureFreeVarLoad struct {
	instr ssa.Instruction
	field string
}

//gocyclo:ignore
func (ea *functionAnalysisState) transferCallIndirect(instrType *ssa.Call, g *EscapeGraph, verbose bool, args []*Node, rets []*Node) {
	// Handle indirect calls. The approach is the same for both indirect and invoke:
	// Loop through all the different out-edges of the func value/receiver. If they are local, we
	// know which MakeClosure/concrete type was used to create that node, so process the ssa.Function.
	// If there are any out-edges to an non-local value (either leaked or escaped), then use the pointer
	// analysis to over-approximate the set of possiblities, and then call each of those.
	pre := g.Clone()
	calleeNode := ea.nodes.ValueNode(instrType.Call.Value)
	nonlocal := g.status[calleeNode] != Local
	for closureNode := range g.Deref(calleeNode) {
		// The closure node represents the actual closure object.
		// Its fields point at allocs which hold the actual data. If the actual
		// data is a pointer to struct/interface, then the alloc will just hold a pointer
		// calleeNode --> closureNode --> new *S --> struct S
		if g.status[closureNode] == Local {
			// Find the corresponding ssa.Function, and perform the invoke
			if concreteCallee, ok := ea.nodes.globalNodes.function[closureNode]; ok {
				summary := ea.prog.summaries[concreteCallee]
				v := pre.Clone()
				if summary != nil {
					// Record our use of this summary for recursion-covergence purposes
					summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph

					// Free vars should be a list of the possible alloc nodes that
					// hold each free var.
					freeVars := [][]*Node{}
					for _, fv := range concreteCallee.FreeVars {
						if IsEscapeTracked(fv.Type()) {
							pointees := []*Node{}
							varFieldNode := pre.FieldSubnode(closureNode, fv.Name(), fv.Type())
							for _, allocNodeEdge := range pre.Edges(varFieldNode, nil, true, true) {
								pointees = append(pointees, allocNodeEdge.dest)
							}
							freeVars = append(freeVars, pointees)
						} else {
							freeVars = append(freeVars, nil)
						}
					}
					v.Call(args, freeVars, rets, summary.finalGraph)
				} else {
					v.CallUnknown(args, rets)
				}
				g.Merge(v)
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
				summary := ea.prog.summaries[concreteCallee]
				if summary != nil {
					// Record our use of this summary for recursion-covergence purposes
					summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph

					for closureNode := range g.Deref(calleeNode) {
						// Check if the closure node itself is non-local (i.e. escaped if it is an argument) and the callee
						// is a closure. In this case, we need to make sure there is at least one node representing the free
						// variables of the closure. Failure to create this node will result in the function essentially
						// assuming the free variables are nil, as there won't be any closure out edges.
						if g.status[closureNode] != Local {
							// Add a load node for external closures, to represent the bound variable storage nodes
							freeVars := [][]*Node{}
							for _, fv := range concreteCallee.FreeVars {
								if IsEscapeTracked(fv.Type()) {
									pointees := []*Node{}
									varFieldNode := pre.FieldSubnode(closureNode, fv.Name(), fv.Type())
									pre.AddEdge(varFieldNode, ea.nodes.LoadNode(closureFreeVarLoad{instrType, fv.Name()}, instrType, NillableDerefType(concreteCallee.FreeVars[0].Type())), false)
									for _, allocNodeEdge := range pre.Edges(varFieldNode, nil, true, true) {
										pointees = append(pointees, allocNodeEdge.dest)
									}
									freeVars = append(freeVars, pointees)
								} else {
									freeVars = append(freeVars, nil)
								}
							}
							v := pre.Clone()
							v.Call(args, freeVars, rets, summary.finalGraph)
							g.Merge(v)
						}
					}
				} else {
					g.CallUnknown(args, rets)
				}
			}
		} else {
			ea.prog.logger.Debugf("Warning, can't resolve indirect of %v, treating as unknown call\n", instrType)
			g.CallUnknown(args, rets)
		}
	}
	if verbose {
		ea.prog.logger.Tracef("After indirect call:\n%v", g.Graphviz())
	}
}

func (ea *functionAnalysisState) transferCallInvoke(instrType *ssa.Call, g *EscapeGraph, verbose bool, args []*Node, rets []*Node) {
	// Find the methods that it could be, according to pointer analysis
	// Invoke each with each possible receiver
	// Note: unlike for indirect calls, we do the full cross product of all possible method implementations
	// with all receivers, even ones that we could deduce aren't possible.
	receiverNode := ea.nodes.ValueNode(instrType.Call.Value)

	if callees, err := ea.getCallees(instrType); err == nil {
		pre := g.Clone()
		for callee := range callees {
			summary := ea.prog.summaries[callee]
			if summary != nil {
				// Record our use of this summary for recursion-covergence purposes
				summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph
				v := pre.Clone()
				if lang.IsNillableType(callee.Params[0].Type()) {
					// The receiver has pointer type, so we're good
					v.Call(append([]*Node{receiverNode}, args...), nil, rets, summary.finalGraph)
					g.Merge(v)
				} else if IsEscapeTracked(callee.Params[0].Type()) {
					// The receiver has struct type, so deref the indirect receiver explicitly
					for x := range pre.Deref(receiverNode) {
						v := pre.Clone()
						v.Call(append([]*Node{x}, args...), nil, rets, summary.finalGraph)
						g.Merge(v)
					}
				} else {
					// The receiver has primitive type, so use a nil receiver
					v.Call(append([]*Node{nil}, args...), nil, rets, summary.finalGraph)
					g.Merge(v)
				}
			} else {
				g.CallUnknown(append([]*Node{receiverNode}, args...), rets)
			}
		}
	} else {
		ea.prog.logger.Debugf("Warning, %v invoke did not find callees, treating as unknown call (err: %v)\n", instrType, err)
		g.CallUnknown(append([]*Node{receiverNode}, args...), rets)
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
		g.CallUnknown(args, rets)
		return nil
	case "ssa:wrapnilchk": // treat as identity fucntion
		g.WeakAssign(rets[0], args[0])
		return nil
	case "delete": // treat as noop, as we don't actually erase information
		return nil
	case "append":
		// ret = append(slice, x)
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
			g.AddEdge(ret, baseArray, true)
		}
		// Then, simulate an allocation. This happens second so we pick up the newly added edges
		allocArray := g.nodes.AllocNode(instr, types.NewArray(sliceType.Elem(), -1))
		for baseArray := range g.Pointees(sliceArg) {
			g.WeakAssign(allocArray, baseArray) // TODO: use a field representing the contents?
		}
		g.AddEdge(ret, allocArray, true)
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
		// sig := builtin.Type().(*types.Signature)
		// sliceType := sig.Params().At(0).Type().Underlying().(*types.Slice)
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
		return fmt.Errorf("unsafe operation %v\n", builtin.Name())
	default:
		return fmt.Errorf("unhandled: %v\n", builtin.Name())
	}
}

type functionAnalysisState struct {
	function     *ssa.Function
	prog         *ProgramAnalysisState
	initialGraph *EscapeGraph                     // the graph on entry to the function. never mutated.
	nodes        *NodeGroup                       // the nodes used in these graphs
	blockEnd     map[*ssa.BasicBlock]*EscapeGraph // the monotone framework result at each basic block end

	// mutability: the finalGraph will never be mutated in place, so saving a reference without Clone() is safe
	finalGraph *EscapeGraph

	// persist the worklist so we can add basic blocks of function calls that changep
	worklist []*ssa.BasicBlock

	// records uses of this summary in other functions, used to trigger re-analysis
	summaryUses map[summaryUse]*EscapeGraph

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

// newFunctionAnalysisState creates a new function analysis for the given function, tied to the given whole program analysis
func newFunctionAnalysisState(f *ssa.Function, prog *ProgramAnalysisState) (ea *functionAnalysisState) {
	nodes := NewNodeGroup(prog.globalNodes)
	initialGraph := NewEmptyEscapeGraph(nodes)
	for _, p := range f.Params {
		var formalNode *Node = nil
		if lang.IsNillableType(p.Type()) {
			paramNode := nodes.ParamNode(p)
			formalNode = nodes.ValueNode(p)
			initialGraph.AddEdge(formalNode, paramNode, true)
		} else if IsEscapeTracked(p.Type()) {
			formalNode = nodes.ValueNode(p)
			initialGraph.AddNode(formalNode)
			initialGraph.MergeNodeStatus(formalNode, Escaped)
		}
		nodes.formals = append(nodes.formals, formalNode)
	}
	for _, p := range f.FreeVars {
		var freeVarNode *Node = nil
		if lang.IsNillableType(p.Type()) {
			paramNode := nodes.ParamNode(p)
			freeVarNode = nodes.ValueNode(p)
			initialGraph.AddEdge(freeVarNode, paramNode, true)
		} else if IsEscapeTracked(p.Type()) {
			freeVarNode = nodes.ValueNode(p)
			initialGraph.AddNode(freeVarNode)
			initialGraph.MergeNodeStatus(freeVarNode, Escaped)
		}
		nodes.freevars = append(nodes.freevars, freeVarNode)
	}
	worklist := []*ssa.BasicBlock{}
	if len(f.Blocks) > 0 {
		worklist = append(worklist, f.Blocks[0])
	}
	return &functionAnalysisState{
		f,
		prog,
		initialGraph,
		nodes,
		make(map[*ssa.BasicBlock]*EscapeGraph),
		NewEmptyEscapeGraph(nodes),
		worklist,
		map[summaryUse]*EscapeGraph{},
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
			ea.transferFunction(instr, g, ea.prog.verbose)
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
			ea.transferFunction(instr, g, ea.prog.verbose)
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

// RunForwardIterative is an implementation of the convergence loop of the monotonic framework.
// Each block is processed, and if it's result changes the successors are added.
func (ea *functionAnalysisState) RunForwardIterative() error {
	if len(ea.function.Blocks) == 0 {
		return nil
	}
	for len(ea.worklist) > 0 {
		block := ea.worklist[0]
		ea.worklist = ea.worklist[1:]
		l := 0
		g := ea.blockEnd[block]
		if g != nil {
			l = len(g.Edges(nil, nil, true, true))
		}
		if l > 10000 {
			return fmt.Errorf("Intermediate graph too large")
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
		false,
		config.NewLogGroup(config.NewDefault()),
		nil,
	}
	analysis := newFunctionAnalysisState(f, prog)
	resummarize(analysis)
	return analysis.finalGraph
}

// Contains the summaries for the entire program. Currently, this is just a simple
// wrapper around a map of function to analysis results, but it will likely need to expand
// to work with the taint analysis.
type ProgramAnalysisState struct {
	summaries   map[*ssa.Function]*functionAnalysisState
	globalNodes *globalNodeGroup
	verbose     bool
	logger      *config.LogGroup
	state       *dataflow.AnalyzerState
}

// (Re)-compute the escape summary for a single function. This will re-run the analysis
// monotone framework loop and update the finalGraph. Returns true if the finalGraph
// changed from its prior version.
func resummarize(ea *functionAnalysisState) (changed bool) {
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
		ea.prog.logger.Warnf("Warning, %v\n", err)
		ea.overflow = true
		for i := range ea.nodes.returnNodes {
			returnResult.AddNode(ea.nodes.ReturnNode(i, types.NewInterfaceType([]*types.Func{}, []types.Type{})))
		}
	}

	// Trim all the nodes unreachable from the external visible ones (params, returns, and globals)
	roots := []*Node{}
	roots = append(roots, returnResult.nodes.formals...)
	roots = append(roots, returnResult.nodes.freevars...)
	for _, x := range returnResult.nodes.returnNodes {
		roots = append(roots, x)
	}
	for node := range returnResult.status {
		if node.kind == KindGlobal {
			roots = append(roots, node)
		}
	}
	returnResult = returnResult.CloneReachable(roots)
	same := ea.finalGraph != nil && ea.finalGraph.Matches(returnResult)
	// The returnResult is always a fresh graph rather than mutating the old one, so we preserve the invariant
	// that the finalGraph never mutates
	ea.finalGraph = returnResult
	return !same
}

var emptySummaryFunctions = map[string]bool{
	"sync/atomic.CompareAndSwapUintptr": true,
	"sync/atomic.CompareAndSwapInt32":   true,
	"sync/atomic.AddInt32":              true,
	"sync.runtime_SemacquireMutex":      true,
	"sync.runtime_Semrelease":           true,
	"sync.throw":                        true,
}

func handlePresummarizedFunction(f *ssa.Function, prog *ProgramAnalysisState) {
	if emptySummaryFunctions[f.String()] {
		prog.logger.Debugf("Using empty summary for: %s\n", f.String())
		prog.summaries[f] = newFunctionAnalysisState(f, prog)
		return
	}
	prog.logger.Debugf("No summary for: %s\n", f.String())
}

// EscapeAnalysis computes the bottom-up escape summaries of functions matching the package filter.
//
//gocyclo:ignore
func EscapeAnalysis(state *dataflow.AnalyzerState, root *callgraph.Node) (*ProgramAnalysisState, error) {
	prog := &ProgramAnalysisState{
		summaries:   make(map[*ssa.Function]*functionAnalysisState),
		verbose:     state.Config.Verbose(),
		globalNodes: newGlobalNodeGroup(),
		logger:      state.Logger,
		state:       state,
	}
	// Find all the nodes that are in the main package, and thus treat everything else as not summarized
	nodes := []*callgraph.Node{}
	for f, node := range state.PointerAnalysis.CallGraph.Nodes {
		if len(f.Blocks) > 0 {
			pkg := lang.PackageTypeFromFunction(f)
			if pkg == nil || state.Config.MatchPkgFilter(pkg.Path()) || state.Config.MatchPkgFilter(pkg.Name()) {
				prog.summaries[f] = newFunctionAnalysisState(f, prog)
				nodes = append(nodes, node)
			} else {
				handlePresummarizedFunction(f, prog)
			}
		} else {
			handlePresummarizedFunction(f, prog)
		}
	}
	if prog.verbose {
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
	worklist := make([]*functionAnalysisState, len(nodes))
	nextIndex := len(worklist) - 1
	for _, scc := range graphutil.StronglyConnectedComponents(nodes, succ) {
		for _, n := range scc {
			if summary, ok := prog.summaries[n.Func]; ok && len(summary.function.Blocks) > 0 {
				worklist[nextIndex] = summary
				nextIndex -= 1
			}
		}
	}
	if nextIndex != -1 {
		panic("expected reverse to be complete")
	}
	// The main worklist algorithm. Reanalyze each function, putting any function(s) that need to be reanalyzed back on
	// the list
	for len(worklist) > 0 {
		summary := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		prog.logger.Tracef("Analyzing %s\n", summary.function.String())
		changed := resummarize(summary)
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
				}
			}
		}
	}
	// Print out the final graphs for debugging purposes
	if prog.verbose {
		for f := range state.PointerAnalysis.CallGraph.Nodes {
			summary := prog.summaries[f]
			if summary != nil && summary.nodes != nil && f.Pkg != nil {
				if f.Pkg.Pkg.Name() == "main" {
					state.Logger.Debugf("Func %s summary is:\n%s\n", f.String(), summary.finalGraph.Graphviz())
				}
			}
		}
	}
	return prog, nil
}

// derefsAreLocal returns true if all of the nodes pointed to by `ptr` are local, i.e.
// not escaped or leaked. Ignores the status of `ptr` itself.
func derefsAreLocal(g *EscapeGraph, ptr *Node) bool {
	for n := range g.Deref(ptr) {
		g.AddNode(n) // Ensure n's status is correct for .IntrinsicStatus nodes() (e.g. globals)
		if g.status[n] != Local {
			return false
		}
	}
	return true
}

// instructionLocality returns true if the given instruction is local w.r.t. the given escape graph.
//
//gocyclo:ignore
func instructionLocality(instr ssa.Instruction, g *EscapeGraph) bool {
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
		} else {
			// arithmetic is local
			return true
		}
	case *ssa.Send:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Chan))
	case *ssa.Range:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
	case *ssa.Next:
		if instrType.IsString {
			return true
		}
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Iter))
	case *ssa.Select:
		local := true
		for _, state := range instrType.States {
			local = local && derefsAreLocal(g, g.nodes.ValueNode(state.Chan))
		}
		return local
	case *ssa.BinOp:
		return true // arithmetic is local
	case *ssa.Go:
		return false // go func is clearly non-local
	case *ssa.Call:
		return false // functions require special handling
	case *ssa.MakeClosure:
		// Making a closure is a local operation. The resulting closure may close over external
		// objects, or may itself leak immediately, but the creation is semantically equivalent
		// to writing some fields in a hidden struct type
		return true
	case *ssa.Defer, *ssa.RunDefers:
		// Defers and rundefers are local, as they in principle just access the stack of defered funcs.
		// Execution of the defered closures, or the process of creating the closures, may be non-local
		// but those are handled elsewhere
		return true
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeChan, *ssa.MakeSlice:
		// All alloc-like operations are local
		return true
	case *ssa.FieldAddr, *ssa.IndexAddr:
		// address calculations don't involve loads
		// TODO: what about ssa.IndexAddr with arrays?
		return true
	case *ssa.Field, *ssa.Index:
		// Field/Index is always applied to a value type, so it does not access memory.
		return true
	case *ssa.Slice, *ssa.SliceToArrayPointer:
		return true // taking sub-slices is an array operation
	case *ssa.MakeInterface, *ssa.Convert,
		*ssa.ChangeInterface, *ssa.ChangeType, *ssa.Phi, *ssa.Extract:
		// conversions and ssa specific things don't access memory
		return true
	case *ssa.TypeAssert:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
	case *ssa.Return, *ssa.Jump, *ssa.If:
		// control flow (at least the operation itself, if not the computation of the argument(s)) is local
		return true
	case *ssa.Panic:
		// Panicing does not itself leak, although it may of course trigger executions that are non-local
		return true
	case *ssa.MapUpdate:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Map))
	case *ssa.Lookup:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
	default:
		// fallthrough to the unhandled case below.
		// Some operation can fallthrough as well, because they might not (yet) handle all forms of their instruction type.
	}
	return false
}

// basicBlockInstructionLocality fills in the locality map with the locality information
// of the instructions in the given basic block.
func basicBlockInstructionLocality(ea *functionAnalysisState, bb *ssa.BasicBlock,
	locality map[ssa.Instruction]bool, callsites map[*ssa.Call]escapeCallsiteInfoImpl) error {
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
		if cl, ok := instr.(*ssa.Call); ok {
			// We need to copy g because it is about to be clobbered by the transfer function
			callsites[cl] = escapeCallsiteInfoImpl{g.Clone(), cl, ea.nodes, ea.prog}
		}
		ea.transferFunction(instr, g, false)
	}
	return nil
}

type escapeCallsiteInfoImpl struct {
	g        *EscapeGraph
	callsite *ssa.Call
	nodes    *NodeGroup
	prog     *ProgramAnalysisState
}

// Does the work of computing instruction locality for a function. See wrapper `ComputeInstructionLocality`.
func computeInstructionLocality(ea *functionAnalysisState, initial *EscapeGraph) (locality map[ssa.Instruction]bool, callsiteInfo map[*ssa.Call]escapeCallsiteInfoImpl) {
	inContextEA := &functionAnalysisState{
		function:     ea.function,
		prog:         ea.prog,
		initialGraph: initial,
		nodes:        ea.nodes,
		blockEnd:     make(map[*ssa.BasicBlock]*EscapeGraph),
		worklist:     []*ssa.BasicBlock{ea.function.Blocks[0]},
	}
	resummarize(inContextEA)
	locality = map[ssa.Instruction]bool{}
	callsites := map[*ssa.Call]escapeCallsiteInfoImpl{}
	for _, block := range ea.function.Blocks {
		basicBlockInstructionLocality(inContextEA, block, locality, callsites)
	}
	if ea.prog.verbose {
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
func TypecheckEscapeGraph(g *EscapeGraph) error {
	typesMap := g.nodes.globalNodes.types
	for n := range g.status {
		tpN := typesMap[n]
		if tpN == nil {
			continue
		}
		if tpN.String() == "invalid type" {
			return fmt.Errorf("Can't have node with invalid type %v:%v", n, tpN)
		}
		realType := tpN.Underlying()
		if n.kind == KindGlobal && !g.IsSubnode(n) {
			realType = NillableDerefType(realType)
		}
		switch tp := realType.(type) {
		case *types.Pointer:
			for _, e := range g.Edges(n, nil, true, true) {
				if g.IsSubnodeEdge(n, e.dest) {
					continue
				}
				destType := typesMap[e.dest]
				if destType == nil {
					continue
				}
				if e.dest.kind == KindGlobal && !g.IsSubnode(e.dest) {
					destType = NillableDerefType(destType)
				}
				if !CanPointTo(tp, destType) {
					return fmt.Errorf("Can't have edge between %v:%v --> %v:%v", n, tpN, e.dest, destType)
				}
			}
		case *types.Struct:
			// TODO: check fields
		}
	}
	return nil
}
