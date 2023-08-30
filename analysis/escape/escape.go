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

// PointerDerefType derefs specifically pointer types (or their aliases). No-op otherwise
func PointerDerefType(t types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Pointer:
		return tt.Elem()
	case *types.Named:
		return PointerDerefType(tt.Underlying())
	default:
		return tt
	}
}

// ChannelContentsType gives the type of the contents of a channel
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

type ReturnUtilityNode struct {
	call        ssa.Instruction
	returnIndex int
}

// transferFunction() computes an instruction's effect on a escape graph.
// Modifies g and nodes in place with the effects of the instruction.
// "Transfer function" is interpreted as in the monotone framework.
//
//gocyclo:ignore
func (ea *functionAnalysisState) transferFunction(instr ssa.Instruction, g *EscapeGraph, verbose bool) {
	// Switch on the instruction to handle each kind of instructions.
	// Some instructions have sub-kinds depending on their arguments, or have alternate comma-ok forms.
	// If an instruction is handled, return. Otherwise, fall through to the end of the function to print
	// a warning about an unhandled instruction. When the set of instructions is complete, this should turn
	// into an error/panic.
	nodes := ea.nodes
	switch instrType := instr.(type) {
	case *ssa.Alloc:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, PointerDerefType(instrType.Type())), true)
		return
	case *ssa.MakeClosure:
		closureNode := nodes.AllocNode(instrType, instrType.Type())
		fn := instrType.Fn.(*ssa.Function)
		nodes.globalNodes.function[closureNode] = fn
		g.AddEdge(nodes.ValueNode(instrType), closureNode, true)
		for i, bindingVal := range instrType.Bindings {
			g.StoreField(nodes.ValueNode(instrType), nodes.ValueNode(bindingVal), fn.FreeVars[i].Name())
		}
		return
	case *ssa.MakeMap:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
		return
	case *ssa.MakeChan:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
		return
	case *ssa.MakeSlice:
		elemType := instrType.Type().Underlying().(*types.Slice).Elem()
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, types.NewArray(elemType, -1)), true)
		return
	case *ssa.FieldAddr:
		for varPointee := range g.Deref(nodes.ValueNode(instrType.X)) {
			g.AddEdgeDirect(Edge{nodes.ValueNode(instrType), varPointee, true, "", instrType.X.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct).Field(instrType.Field).Name()})
		}
		return
	case *ssa.IndexAddr:
		// raw array is different than *array and slice
		if _, ok := instrType.X.Type().Underlying().(*types.Array); ok {
			// Array case. It is unclear how this is generated, and what the semantics should be in this case.
			panic("IndexAddr of direct array")
		} else {
			// *array or slice
			for varPointee := range g.Deref(nodes.ValueNode(instrType.X)) {
				g.AddEdge(nodes.ValueNode(instrType), varPointee, true)
			}
			return
		}
	case *ssa.Store:
		if lang.IsNillableType(instrType.Val.Type()) {
			g.Store(nodes.ValueNode(instrType.Addr), nodes.ValueNode(instrType.Val))
		} else if IsEscapeTracked(instrType.Val.Type()) {
			// Handle struct types
			valNode := nodes.ValueNode(instrType.Val)
			// When copying from a non-local struct
			if g.status[valNode] != Local {
				loadNode := nodes.LoadNode(instr, PointerDerefType(instrType.Val.Type().Underlying()))
				g.AddEdge(valNode, loadNode, false)
			}
			g.Store(nodes.ValueNode(instrType.Addr), nodes.ValueNode(instrType.Val))
		}
		return
	case *ssa.UnOp:
		// Check if this is a load operation
		if _, ok := instrType.X.Type().(*types.Pointer); ok && instrType.Op == token.MUL {
			if IsEscapeTracked(instrType.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, PointerDerefType(instrType.X.Type().Underlying()))
				}
				// fmt.Printf("Loading\n")
				g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			}
			return
		} else if _, ok := instrType.X.Type().(*types.Chan); ok && instrType.Op == token.ARROW {
			// recv on channel
			if IsEscapeTracked(instrType.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, ChannelContentsType(instrType.X.Type().Underlying()))
				}
				g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			}
			return
		} else {
			// arithmetic UnOp: no-op
			return
		}
	case *ssa.Send:
		if IsEscapeTracked(instrType.X.Type()) {
			// Send on channel is a write to the contents "field" of the channel
			g.StoreField(nodes.ValueNode(instrType.Chan), nodes.ValueNode(instrType.X), "contents")
		}
		return
	case *ssa.Slice:
		switch tp := instrType.X.Type().Underlying().(type) {
		case *types.Slice:
			// Slice of slice, basic copy
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
			return
		case *types.Basic:
			if tp.Kind() != types.String && tp.Kind() != types.UntypedString {
				panic("Slice of BasicKind that isn't string: " + tp.String())
			}
			// Slice of a string creates a hidden allocation of an array to hold the string contents.
			g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, tp), true)
			return
		case *types.Pointer:
			if _, ok := tp.Elem().Underlying().(*types.Array); !ok {
				panic("Slice of pointer to non-array?")
			}
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
			return
		}
	case *ssa.Return:
		return
	case *ssa.Jump:
		return
	case *ssa.If:
		return
	case *ssa.Select:
		recvIndex := 2 // for tuple sensitivity, this will be the index that should be read in the result tuple.
		for _, st := range instrType.States {
			if st.Dir == types.RecvOnly {
				if IsEscapeTracked(ChannelContentsType(st.Chan.Type())) {
					// TODO: This should be one load node per branch, so that different types
					// get different nodes. This is only important if we are tuple sensitive and
					// make the graph typed. For now, the different cases can safely share nodes,
					// which is imprecise but sound.
					gen := func() *Node {
						return nodes.LoadNode(instr, ChannelContentsType(st.Chan.Type()))
					}
					tmpNode := nodes.TempNode(ReturnUtilityNode{instrType, recvIndex})
					g.Load(tmpNode, nodes.ValueNode(st.Chan), gen)
					tupleNode := nodes.ValueNode(instrType)
					for _, tmpEdge := range g.DerefEdges(tmpNode) {
						g.AddEdgeDirect(Edge{tupleNode, tmpEdge.dest, tmpEdge.isInternal, fmt.Sprintf("#%d", recvIndex), tmpEdge.destField})
					}
				}
				recvIndex += 1
			} else if st.Dir == types.SendOnly {
				if IsEscapeTracked(st.Send.Type()) {
					// Send on channel is a write to the contents "field" of the channel
					g.StoreField(nodes.ValueNode(st.Chan), nodes.ValueNode(st.Send), "contents")
				}
			} else {
				panic("Unexpected ")
			}
		}
		return
	case *ssa.Panic:
		g.CallUnknown([]*Node{nodes.ValueNode(instrType.X)}, []*Node{nodes.UnusedNode()})
		return
	case *ssa.Call:
		// Build the argument array, consisting of the nodes that are the concrete arguments
		// Nil nodes are used for things that aren't pointer-like, so that they line up with
		// the formal parameter definitions.
		args := make([]*Node, len(instrType.Call.Args))
		for i, arg := range instrType.Call.Args {
			if IsEscapeTracked(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		// For now, we just have one return value that is the merged representation of all of
		// them. For proper tuple-sensitive results, we would need to make this match the real
		// number of return values, and find out which extract operations we should assign the
		// results to.
		rets := []*Node{}
		nReturns := instrType.Call.Signature().Results().Len()
		if nReturns > 1 {
			for i := 0; i < nReturns; i++ {
				rets = append(rets, nodes.TempNode(ReturnUtilityNode{instrType, i}))
			}
		} else {
			rets = append(rets, nodes.ValueNode(instrType))
		}

		if builtin, ok := instrType.Call.Value.(*ssa.Builtin); ok {
			err := g.CallBuiltin(instrType, builtin, args, rets)
			if err != nil {
				ea.prog.logger.Warnf("Warning, escape analysis does not handle builtin: %s", err)
			}
		} else if callee := instrType.Call.StaticCallee(); callee != nil {
			ea.transferCallStaticCallee(instrType, g, verbose, args, rets)
		} else if instrType.Call.IsInvoke() {
			// If no static callee, either we have an indirect call, e.g. t3(t4) or a method invocation,
			// e.g. invoke t3.Method(t8, t13).
			ea.transferCallInvoke(instrType, g, verbose, args, rets)
		} else {
			//  Indirect call callees can be closures, bound methods, regular named functions, or thunks.
			ea.transferCallIndirect(instrType, g, verbose, args, rets)
		}

		returnNode := nodes.ValueNode(instrType)
		if nReturns > 1 {
			for i := 0; i < instrType.Call.Signature().Results().Len(); i++ {
				for _, retEdge := range g.DerefEdges(rets[i]) {
					g.AddEdgeDirect(Edge{returnNode, retEdge.dest, retEdge.isInternal, fmt.Sprintf("#%d", i), retEdge.destField})
				}
			}
		}

		return

	case *ssa.Go:
		args := make([]*Node, len(instrType.Call.Args))
		for i, arg := range instrType.Call.Args {
			if IsEscapeTracked(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		rets := []*Node{nodes.UnusedNode()}
		// A go call always leaks arguements. The return value is irrelevant (`_`).
		g.CallUnknown(args, rets)
		return
	case *ssa.Defer:
	case *ssa.Field:
		if IsEscapeTracked(instrType.Type()) {
			// TODO: this should be a field-specific assignment
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
			// TODO: make this better, really!!!
		}
		return
	case *ssa.Index:
		switch tp := instrType.X.Type().Underlying().(type) {
		case *types.Basic:
			if tp.Kind() == types.String || tp.Kind() == types.UntypedString {
				// string index is no-op
				return
			}
		case *types.Slice:
			gen := func() *Node { return nodes.LoadNode(instr, PointerDerefType(PointerDerefType(instrType.X.Type()))) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			return
		case *types.Array:
			if IsEscapeTracked(instrType.Type()) {
				g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
			}
			return
		}
	case *ssa.Lookup:
		if IsEscapeTracked(instrType.Type().Underlying()) {
			gen := func() *Node { return nodes.LoadNode(instr, instrType.Type()) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
		}
		return
	case *ssa.MapUpdate:
		if IsEscapeTracked(instrType.Value.Type()) {
			g.StoreField(nodes.ValueNode(instrType.Map), nodes.ValueNode(instrType.Value), "values[*]")
		}
		if IsEscapeTracked(instrType.Key.Type()) {
			g.StoreField(nodes.ValueNode(instrType.Map), nodes.ValueNode(instrType.Key), "keys[*]")
		}
		return
	case *ssa.Next:
		if !instrType.IsString {
			gen := func() *Node {
				return nodes.LoadNode(instr, PointerDerefType(PointerDerefType(instrType.Iter.Type())))
			}
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.Iter), gen)
		}
		return
	case *ssa.Range:
		if _, ok := instrType.X.Type().Underlying().(*types.Map); ok {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		} else {
			// range over string, not interesting to escape
			return
		}
		return
	case *ssa.MakeInterface:
		if IsEscapeTracked(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		} else {
			g.AddNode(nodes.ValueNode(instrType)) // Make interface from string or other non-pointer type
		}
		return
	case *ssa.TypeAssert:
		if IsEscapeTracked(instrType.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		}
		return
	case *ssa.Convert:
		if IsEscapeTracked(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		} else if _, ok := instrType.Type().Underlying().(*types.Slice); ok {
			if basic, ok := instrType.X.Type().Underlying().(*types.Basic); ok &&
				(basic.Kind() == types.String || basic.Kind() == types.UntypedString) {
				// We must be converting a string to a slice, so the semantics are to do a hidden allocation
				g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
			}
		}
		return
	case *ssa.ChangeInterface:
		g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		return
	case *ssa.ChangeType:
		if IsEscapeTracked(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X))
		}
		return
	case *ssa.Phi:
		if IsEscapeTracked(instrType.Type()) {
			for _, v := range instrType.Edges {
				// TODO: this erases any src fiels from v, which might be important for value structs
				// with pointer arguments
				g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(v))
			}
		}
		return
	case *ssa.Extract:
		if _, ok := instrType.Tuple.(*ssa.Phi); ok {
			panic("Extract from phi?")
		}
		if IsEscapeTracked(instrType.Type()) {
			// Note: this is not tuple-sensitive. Because the SSA does not appear to separate the extract
			// op from the instruction that generates the tuple, we could save the precise information about
			// tuples on the side and lookup the correct node(s) here as opposed to collapsing into a single
			// node for the entire tuple.
			src := nodes.ValueNode(instrType.Tuple)
			dest := nodes.ValueNode(instrType)
			for _, e := range g.DerefEdges(src) {
				if e.srcField == "" {
					ea.prog.logger.Warnf("Tuple with unlabeled edge: %v \n", instrType.Tuple)
				}
				if e.srcField == fmt.Sprintf("#%d", instrType.Index) || e.srcField == "" {
					g.AddEdgeDirect(Edge{dest, e.dest, e.isInternal, "", e.destField})
				}
			}
		}
		return
	case *ssa.BinOp:
		return
	default:
	}
	if ea.prog.logger.LogsDebug() {
		pos := instr.Parent().Prog.Fset.Position(instr.Pos())
		ea.prog.logger.Debugf("Unhandled: (type: %s) %v at %v\n", reflect.TypeOf(instr).String(), instr, pos)
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
		fmt.Printf("Warning, %v is not a summarized function: treating as unknown call\n",
			callee.String())
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
							for _, allocNodeEdge := range pre.Edges(closureNode, nil, true, true) {
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
							if len(concreteCallee.FreeVars) > 0 {
								pre.AddEdge(closureNode, ea.nodes.LoadNode(instrType, concreteCallee.FreeVars[0].Type()), false)
							}
							freeVars := [][]*Node{}
							for _, fv := range concreteCallee.FreeVars {
								if IsEscapeTracked(fv.Type()) {
									pointees := []*Node{}
									for _, allocNodeEdge := range pre.Edges(closureNode, nil, true, true) {
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
	argsWithReceiver := []*Node{receiverNode}
	for _, a := range args {
		argsWithReceiver = append(argsWithReceiver, a)
	}
	argsWithNilReceiver := []*Node{nil}
	for _, a := range args {
		argsWithNilReceiver = append(argsWithNilReceiver, a)
	}

	if callees, err := ea.getCallees(instrType); err == nil {
		pre := g.Clone()
		for callee := range callees {
			summary := ea.prog.summaries[callee]
			if summary != nil {
				// Record our use of this summary for recursion-covergence purposes
				summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph
				v := pre.Clone()
				appropriateArgs := argsWithReceiver
				if !IsEscapeTracked(callee.Params[0].Type()) {
					appropriateArgs = argsWithNilReceiver
				}
				v.Call(appropriateArgs, nil, rets, summary.finalGraph)
				g.Merge(v)
			} else {
				g.CallUnknown(args, rets)
			}
		}
	} else {
		ea.prog.logger.Debugf("Warning, %v invoke did not find callees, treating as unknown call (err: %v)\n", instrType, err)
		g.CallUnknown(argsWithReceiver, rets)
	}
	if ea.prog.logger.LogsTrace() {
		ea.prog.logger.Tracef("After invoke call:\n%v", g.Graphviz())
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
			initialGraph.JoinNodeStatus(formalNode, Escaped)
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
			initialGraph.JoinNodeStatus(freeVarNode, Escaped)
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
	}
}

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
		ppInstr := instr.String()
		if v, ok := instr.(ssa.Value); ok {
			ppInstr = v.Name() + " = " + ppInstr
		}
		if ea.function.String() == "(*fmt.pp).fmtBytes" || ea.function.String() == "(*fmt.pp).printValue" || ea.function.String() == "(*fmt.pp).fmtPointer" {
			fmt.Printf("Processing %s\n", ppInstr)
		}
		// Check the monotonicity of the transfer function.
		if checkMonotonicityEveryInstruction {
			pre := g.Clone()
			ea.transferFunction(instr, g, ea.prog.verbose)
			post := g.Clone()
			if pairs, ok := instructionMonoCheckData[instr]; ok {
				for _, p := range pairs {
					// Directly check
					if less, _ := p.input.LessEqual(pre); less {
						if lessOut, reason := p.output.LessEqual(post); !lessOut {
							fmt.Printf("Monotonicity violation at %v because %s\n", instr, reason)
							fmt.Printf("A <= B but !(C <= D)\nA (old pre):\n%v\nB (new pre):\n%v\nC (old post):\n%v\nD (new post):\n%v\n",
								p.input.Graphviz(),
								pre.Graphviz(),
								p.output.Graphviz(),
								post.Graphviz())
							// panic("monontonicity violation")
						}
					}
				}
			}
			instructionMonoCheckData[instr] = append(instructionMonoCheckData[instr], cachedGraphMonotonicity{pre, post})
		} else {
			ea.transferFunction(instr, g, ea.prog.verbose)
		}
		if ea.function.String() == "(*fmt.pp).fmtBytes" || ea.function.String() == "(*fmt.pp).printValue" || ea.function.String() == "(*fmt.pp).fmtPointer" {
			fmt.Printf("Graph after instruction %s is\n%s\n", ppInstr, g.Graphviz())
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
func (e *functionAnalysisState) addToBlockWorklist(block *ssa.BasicBlock) {
	found := false
	for _, entry := range e.worklist {
		if entry == block {
			found = true
		}
	}
	if !found {
		e.worklist = append(e.worklist, block)
	}
}

// RunForwardIterative is an implementation of the convergence loop of the monotonic framework.
// Each block is processed, and if it's result changes the successors are added.
func (e *functionAnalysisState) RunForwardIterative() {
	if len(e.function.Blocks) == 0 {
		return
	}
	for len(e.worklist) > 0 {
		block := e.worklist[0]
		e.worklist = e.worklist[1:]
		if e.ProcessBlock(block) {
			for _, nextBlock := range block.Succs {
				e.addToBlockWorklist(nextBlock)
			}
		}
	}
}

// EscapeSummary computes the escape summary for a single function, independently of all other functions.
// Other functions are treated as arbitrary.
func EscapeSummary(f *ssa.Function) (graph *EscapeGraph) {
	prog := &ProgramAnalysisState{make(map[*ssa.Function]*functionAnalysisState), &globalNodeGroup{0, make(map[*Node]*ssa.Function)}, false, config.NewLogGroup(config.NewDefault()), nil}
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
func resummarize(analysis *functionAnalysisState) (changed bool) {
	analysis.RunForwardIterative()
	returnResult := NewEmptyEscapeGraph(analysis.nodes)
	for block, blockEndState := range analysis.blockEnd {
		if len(block.Instrs) > 0 {
			if retInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
				returnResult.Merge(blockEndState)
				for i, rValue := range retInstr.Results {
					if IsEscapeTracked(rValue.Type()) {
						returnResult.WeakAssign(analysis.nodes.ReturnNode(i), analysis.nodes.ValueNode(rValue))
					}
				}
			}
		}
	}

	// Trim all the nodes unreachable from the external visable ones (params, returns, and globals)
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
	// fmt.Printf("Before:\n%v\n", returnResult.Graphviz())
	returnResult = returnResult.CloneReachable(roots)
	// fmt.Printf("After:\n%v\n", returnResult.Graphviz())
	same := analysis.finalGraph != nil && analysis.finalGraph.Matches(returnResult)
	// The returnResult is always a fresh graph rather than mutating the old one, so we preserve the invariant
	// that the finalGraph never mutates
	analysis.finalGraph = returnResult
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
		fmt.Printf("Using empty summary for: %s\n", f.String())
		prog.summaries[f] = newFunctionAnalysisState(f, prog)
		return
	}
	fmt.Printf("No summary for: %s\n", f.String())
}

// EscapeAnalysis computes the bottom-up escape summaries of functions matching the package filter.
//
//gocyclo:ignore
func EscapeAnalysis(state *dataflow.AnalyzerState, root *callgraph.Node) (*ProgramAnalysisState, error) {
	prog := &ProgramAnalysisState{
		summaries:   make(map[*ssa.Function]*functionAnalysisState),
		verbose:     state.Config.Verbose(),
		globalNodes: &globalNodeGroup{0, make(map[*Node]*ssa.Function)},
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
		funcName := summary.function.Name()

		extraDebug := true
		// Block of debugging info. If this survives to PR, I've made a mistake!
		var oldFinalGraph *EscapeGraph
		if extraDebug {
			state.Logger.Infof("Analyzing %v\n", summary.function.String())
			oldFinalGraph = summary.finalGraph // final graphs are not updated in place so this is safe
		}
		changed := resummarize(summary)
		if extraDebug {
			if state.Logger.LogsTrace() || summary.function.String() == "(*fmt.pp).fmtFloat" || summary.function.String() == "(*crypto/internal/nistec.P224Point).Double" || true {
				state.Logger.Infof("Func %s is (changed=%v):\n%s\n", summary.function.String(), changed, summary.finalGraph.GraphvizLabel(funcName))
			}
			if less, rationale := oldFinalGraph.LessEqual(summary.finalGraph); !less {
				nEdges := len(summary.finalGraph.Edges(nil, nil, true, true))
				err := fmt.Errorf("Summary (%d edges) for %v is not monotone: %v ()\n", nEdges, summary.function.String(), rationale)
				state.Logger.Errorf("%v", err)
				if nEdges < 50 {
					fmt.Printf("Old: \n%v\nNew: \n%v\n", oldFinalGraph.Graphviz(), summary.finalGraph.Graphviz())
				}
				// return nil, err
			}
			state.Logger.Infof("size of summary: %v nodes %v edges\n", len(summary.finalGraph.status), len(summary.finalGraph.Edges(nil, nil, true, true)))
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
					state.Logger.Debugf("Func %s summary is:\n%s\n", f.String(), summary.finalGraph.GraphvizLabel(f.String()))
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
