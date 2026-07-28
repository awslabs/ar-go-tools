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
	"context"
	"errors"
	"fmt"
	"go/token"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// filterFlowsRead returns the flows that were unproven after performing the read analysis.
// The read analysis filters out all flows that do not access their input value(s).
// If an input value is not accessed (unread), then it is impossible to have data flow from it.
func filterFlowsRead(ctx context.Context, s *State, flows []flow) []flow {
	var unproven []flow
	for _, fl := range flows {
		mustNotFlow, err := mustNotFlowRead(ctx, s, fl)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Analysis timed out: return all unproven flows computed so far.
				unproven = append(unproven, fl)
				break
			}
		}
		// NOTE Maybe we shouldn't bother checking the rest since the summary is unsound, but
		// including all the unproven flows makes it easier to test.
		if !mustNotFlow {
			unproven = append(unproven, fl)
		}
	}

	return unproven
}

func mustNotFlowRead(ctx context.Context, s *State, fl flow) (bool, error) {
	vals := inputVals(fl)
	for _, val := range vals {
		if _, ok := s.unreadVals[value{val, fl.from.path}]; !ok {
			ri, ok, err := checkReads(ctx, s, val, fl.from.path)
			if err != nil {
				return false, fmt.Errorf(
					"failed to check reads from flow input value %v: %w", val, err)
			}
			if ok {
				s.Logger.Tracef(
					"found access of flow input value %v with path %q in must-not-flow %v: read %v at %s\n",
					val, fl, fl.to.path, ri, s.Program.Fset.Position(ri.Pos()))
				return false, nil
			}
		}

		s.unreadVals[value{val, fl.from.path}] = struct{}{}
	}

	return true, nil
}

// checkReads returns an instruction that reads anything from val's underlying memory, given the
// path pth.
// If it returns false, there are no reads.
//
// It is an inter-procedural analysis which checks for reads in the value's enclosing function and
// its callees in BFS order.
//
//gocyclo:ignore
func checkReads(ctx context.Context, s *State, val ssa.Value, pth path) (readInstr, bool, error) {
	cg := s.PointerAnalysis.CallGraph
	queue := []*callgraph.Node{cg.Nodes[val.Parent()]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})

	ids := nodeIds(s.cache, val)
	s.Logger.Tracef("node ids of flow input value %v (%v): %v\n", val, val.Type(), ids)

	for len(queue) > 0 {
		// This function can take a while so handle timeouts
		select {
		case <-ctx.Done():
			return readInstr{}, false, ctx.Err()
		default:
		}

		node := queue[0]
		queue = queue[1:]
		if _, ok := seen[node]; ok {
			continue
		}
		seen[node] = struct{}{}
		if node.Func == nil {
			return readInstr{}, false, nil
		}

		var res readInstr
		wasRead := false
		// A function may be visited multiple times in different calling contexts so only analyze
		// each function once.
		if _, ok := seenFunc[node.Func]; ok {
			continue
		}
		seenFunc[node.Func] = struct{}{}

		s.Logger.Tracef(
			"checking for reads from memory of %v (%v) through access path %v in function %s\n",
			val, val.Type(), pth, node.Func)

		lang.IterateInstructions(node.Func, func(_ int, instr ssa.Instruction) {
			read, ok := valsReadFrom(instr)
			if !ok {
				return
			}

			for _, rval := range read.values {
				if rval == val {
					if pth.len() == 0 {
						wasRead = true
						res = read
						return
					}

					// Field-sensitivity: a struct field can only be read via a *ssa.Field or
					// *ssa.FieldAddr instruction.
					//
					// TODO Keep track of field accesses to handle path lengths > 1.
					switch instr := read.Instruction.(type) {
					case *ssa.Field:
						info := analysisutil.FieldFieldInfo(instr)
						if pth.len() == 1 && strings.HasSuffix(pth.String(), info.FieldName) {
							wasRead = true
							res = read
							return
						}
					case *ssa.FieldAddr:
						info := analysisutil.FieldAddrFieldInfo(instr)
						if pth.len() == 1 && strings.HasSuffix(pth.String(), info.FieldName) {
							wasRead = true
							res = read
							return
						}
					}
				}

				// If the read objects have any of the same node ids as the input value, then
				// the read instruction reads a value from the input value's memory.
				mlabels := s.cache.Labels(rval)
				for mlabel := range mlabels {
					mobj := mlabel.Obj()
					found := false
					for _, mid := range mobj.NodeIDs() {
						if ids.Has(int(mid)) {
							found = true
							break
						}
					}
					if !found {
						continue
					}

					if pth.len() > 0 && len(mlabel.Path()) > 0 {
						// If there is a path (field-sensitive), then only check writes to objects
						// of that field's memory.
						if !newPath(mlabel.Path(), maxPathLen).isCoveredBy(pth) {
							continue
						}
					}
					if dataVal, ok := mobj.Data().(ssa.Value); ok {
						s.Logger.Tracef(
							"found read from val %v data: val node ids: %v, read source: %v, object: %v "+
								"(SSA name: %v), path: %v\n",
							val, ids, rval, mobj, dataVal.Name(), pth)
					} else {
						s.Logger.Tracef(
							"found read from val %v data: val node ids: %v, read source: %v, object: %v, path: %v\n",
							val, ids, rval, mobj, pth)
					}
					wasRead = true
					res = read
					return
				}
			}
		})

		if wasRead {
			return res, true, nil
		}

		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
	}

	return readInstr{}, false, nil
}

// readInstr is an instruction that reads from an SSA value's underlying memory.
type readInstr struct {
	ssa.Instruction
	values []ssa.Value // values are the values that are read from (r-values).
}

func (r readInstr) String() string {
	return fmt.Sprintf("from %v via %v in %s", r.values, r.Instruction, r.Instruction.Parent())
}

// valsReadFrom returns a read instruction containing all the non-nil values read from instr.
func valsReadFrom(instr ssa.Instruction) (readInstr, bool) {
	var rvals []ssa.Value
	add := func(vs ...ssa.Value) {
		for _, v := range vs {
			if v == nil {
				continue
			}

			rvals = append(rvals, v)
		}
	}

	switch instr := instr.(type) {
	case ssa.CallInstruction:
		add(lang.GetArgs(instr)...)
	case *ssa.Index:
		add(instr.X)
	case *ssa.Lookup:
		add(instr.X, instr.Index)
	case *ssa.Slice:
		add(instr.X)
	case *ssa.UnOp:
		// Dereference y = *x
		if instr.Op == token.MUL {
			add(instr.X)
		}
		// Channel receive y <- x
		if instr.Op == token.ARROW {
			add(instr.X)
		}
	case *ssa.Field:
		add(instr.X)
	case *ssa.FieldAddr:
		add(instr.X)
	case *ssa.BinOp:
		add(instr.X, instr.Y)
	case *ssa.IndexAddr:
		add(instr.X, instr.Index)
	case *ssa.MapUpdate:
		add(instr.Key, instr.Value)
	case *ssa.Panic:
		add(instr.X)
	case *ssa.Phi:
		add(instr.Edges...)
	case *ssa.Range:
		add(instr.X)
	case *ssa.Return:
		add(instr.Results...)
	case *ssa.Send:
		add(instr.X)
	case *ssa.Store:
		add(instr.Val)
	}

	if len(rvals) == 0 {
		return readInstr{Instruction: instr, values: nil}, false
	}

	return readInstr{Instruction: instr, values: rvals}, true
}

// inputVals returns all of the SSA values that the flow's "from" node may refer to.
func inputVals(fl flow) []ssa.Value {
	var vals []ssa.Value
	switch to := fl.from.node.(type) {
	// TODO handle globals
	case *dataflow.ParamNode:
		vals = append(vals, to.SsaNode())
	case *dataflow.FreeVarNode:
		vals = append(vals, to.SsaNode())
	default:
		panic(fmt.Errorf("unhandled flow input node type: %T", fl.to))
	}

	return vals
}
