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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/container/intsets"
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
// For each instruction, it uses two independent, complementary mechanisms to decide whether the
// instruction reads (val, pth) -- neither one alone is sound/complete for every SSA shape, so
// both are tried and either one matching is sufficient:
//
//   - matchesViaFieldChain walks the SSA structure of nested *ssa.Field/*ssa.FieldAddr operand
//     chains directly, independent of the pointer analysis. It exists because stack-allocated
//     values that never escape have no points-to information, so matchesViaPointsTo can't see
//     them at all. It only understands simple field-chain and Alloc-spill shapes, so a non-match
//     does not prove the instruction is irrelevant.
//   - matchesViaPointsTo uses the pointer analysis (val's and the read operands' NodeIDs()) to
//     decide aliasing in the general case, including through calls and arbitrary indirection
//     that matchesViaFieldChain does not understand.
//
//gocyclo:ignore
func checkReads(ctx context.Context, s *State, val ssa.Value, pth path) (readInstr, bool, error) {
	cg := s.PointerAnalysis.CallGraph
	queue := []*callgraph.Node{cg.Nodes[val.Parent()]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})

	ids := nodeIds(s.cache, val)
	if s.Logger != nil {
		for lbl := range s.cache.Labels(val) {
			s.Logger.Tracef(
				"  label for %v: obj=%p value=%v pos=%v\n",
				val, lbl.Obj(), lbl.Value(), lbl.Pos())
		}
	}
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

			if matchesViaFieldChain(instr, val, pth) {
				wasRead = true
				res = read
				return
			}

			if matchesViaPointsTo(s, val, ids, pth, read) {
				wasRead = true
				res = read
				return
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

// matchesViaFieldChain reports whether instr definitively reads (val, pth) based purely on SSA
// field-access structure, independent of the pointer analysis. It exists because stack-allocated
// values that never escape have no points-to information (see matchesViaPointsTo, which finds
// nothing for such values).
//
// A struct field can only be read via a *ssa.Field or *ssa.FieldAddr instruction, and each such
// instruction addresses exactly one field. This walks the chain of nested field accesses
// backward from instr: if it matches pth exactly, all the way down to val, instr definitively
// reads pth. This covers pth.len() > 1 (e.g. val.a.b) and by-value struct parameters spilled to a
// local *ssa.Alloc (see fieldPathMatches/allocInitializedFrom), neither of which
// matchesViaPointsTo's rval == val check detects on its own.
//
// A false result does not by itself prove instr is irrelevant: the chain walk does not understand
// every SSA shape (e.g. aliasing through calls), so callers must still try matchesViaPointsTo
// rather than skip the instruction outright.
func matchesViaFieldChain(instr ssa.Instruction, val ssa.Value, pth path) bool {
	if pth.len() == 0 {
		return false
	}
	switch instr.(type) {
	case *ssa.Field, *ssa.FieldAddr:
		return fieldPathMatches(instr, val, pth)
	default:
		return false
	}
}

// matchesViaPointsTo reports whether read reads (val, pth), using val's ids (from the pointer
// analysis) to decide aliasing in the general case that matchesViaFieldChain's structural walk
// does not understand (e.g. aliasing through calls or arbitrary indirection). It is the fallback
// used when matchesViaFieldChain does not find a match; it is blind to values with no points-to
// information (e.g. non-escaping stack locals), which is why matchesViaFieldChain exists
// alongside it.
func matchesViaPointsTo(s *State, val ssa.Value, ids *intsets.Sparse, pth path, read readInstr) bool {
	for _, rval := range read.values {
		if rval == val {
			if pth.len() == 0 {
				return true
			}

			// Same-node, single-level field check: instr's operand is val directly (no
			// intermediate Alloc/copy or nested chain). matchesViaFieldChain already covers this
			// case (and the pth.len() > 1 / Alloc-spill cases) when it succeeds; this only needs
			// to rule out a *mismatched* field on val itself, so this instruction (definitively
			// about a different field) is skipped rather than falling through to the generic
			// mlabels check below, which would otherwise re-match on any sibling field of the
			// same object (e.g. a *ssa.FieldAddr for &c.Body must not count as touching
			// c.BodyStart).
			switch instr := read.Instruction.(type) {
			case *ssa.Field:
				info := analysisutil.FieldFieldInfo(instr)
				if pth.len() == 1 && pth[0] == info.FieldName {
					return true
				}
				continue
			case *ssa.FieldAddr:
				info := analysisutil.FieldAddrFieldInfo(instr)
				if pth.len() == 1 && pth[0] == info.FieldName {
					return true
				}
				continue
			}
		}

		// If the read objects have any of the same node ids as the input value, then the read
		// instruction reads a value from the input value's memory.
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
			return true
		}
	}
	return false
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
		// A FieldAddr only computes an address (&x.Field); it does not itself read the field's
		// value. Treat it as reading instr.X only if the computed address is actually
		// dereferenced for its value somewhere (e.g. *p), not merely used as a write
		// destination (e.g. *p = v, which is a write, not a read of the prior value).
		if fieldAddrIsDereferenced(instr) {
			add(instr.X)
		}
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

// fieldAddrIsDereferenced returns true if instr's result (a field address, &x.Field) is ever
// dereferenced for its value (e.g. via *p, or passed to another instruction that reads through
// it), as opposed to being used only as a write destination (e.g. *p = v, or being passed to a
// FieldAddr computing a nested field's address). Computing a field's address is not itself a
// read of that field: `t1 = &x.Body` followed only by `*t1 = v` is a write to x.Body, not a read
// of the value x.Body held before the write.
func fieldAddrIsDereferenced(instr *ssa.FieldAddr) bool {
	refs := instr.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch ref := ref.(type) {
		case *ssa.UnOp:
			// *t1 dereferences the address to read its value.
			if ref.Op == token.MUL && ref.X == instr {
				return true
			}
		case *ssa.Store:
			// *t1 = v is a write through t1, not a read: ref.Val (not ref.Addr) is the value
			// being written, and t1 (the FieldAddr result) is only ever ref.Addr here, never
			// ref.Val. No read of the field's prior value occurs.
			continue
		case *ssa.FieldAddr:
			// A nested field access (&(&x.Field).Nested) navigates through the outer address;
			// conservatively treat this as a read only if the nested access is itself
			// dereferenced.
			if fieldAddrIsDereferenced(ref) {
				return true
			}
		default:
			// Any other use (passed as a call argument, stored into another variable, returned,
			// etc.) may lead to the field being read somewhere we don't track locally.
			// Conservatively treat it as a read to avoid unsoundness.
			return true
		}
	}
	return false
}

// fieldPathMatches returns true if instr (a *ssa.Field or *ssa.FieldAddr) is the innermost step
// of a chain of nested field accesses that exactly matches pth, all the way down to val: e.g.
// for pth = [.Src, .X], instr must address field X of some value that is itself instr2.X where
// instr2 addresses field Src of val.
//
// This walks purely on SSA structure (Field/FieldAddr/UnOp/Alloc), independent of the pointer
// analysis, so it remains sound for stack-allocated values that never escape and therefore have
// no points-to information (see checkReads' ids/mlabels fallback, which silently finds nothing
// for such values).
func fieldPathMatches(instr ssa.Instruction, val ssa.Value, pth path) bool {
	// Walk from the last segment of pth to the first, matching each one against a step in the
	// instr chain, until pth is exhausted (then instr's receiver must be val) or a mismatch.
	for i := pth.len() - 1; i >= 0; i-- {
		var fieldName string
		var receiver ssa.Value
		switch instr := instr.(type) {
		case *ssa.Field:
			fieldName = analysisutil.FieldFieldInfo(instr).FieldName
			receiver = instr.X
		case *ssa.FieldAddr:
			fieldName = analysisutil.FieldAddrFieldInfo(instr).FieldName
			receiver = instr.X
		default:
			return false
		}
		if fieldName != pth[i] {
			return false
		}
		if i == 0 {
			if receiver == val {
				return true
			}
			// A by-value struct parameter is spilled to a local *ssa.Alloc so its fields can be
			// addressed (e.g. c nestedTwoFields lowers to a local Alloc, with *alloc = c
			// storing the parameter's value into it). Recognize this pattern: the chain
			// bottoms out at val if receiver is such an Alloc.
			return allocInitializedFrom(receiver, val)
		}
		// More segments remain: the receiver of this step must itself be a Field/FieldAddr
		// instruction addressing the previous segment. If receiver is a *ssa.UnOp dereference
		// (e.g. *ssa.FieldAddr's result is dereferenced before the next field is accessed via
		// *ssa.Field on the dereferenced value), unwrap it to continue the chain.
		if unop, ok := receiver.(*ssa.UnOp); ok && unop.Op == token.MUL {
			receiver = unop.X
		}
		nextInstr, ok := receiver.(ssa.Instruction)
		if !ok {
			return false
		}
		instr = nextInstr
	}
	// pth.len() == 0 never reaches here (checked by the caller), but guard defensively.
	return pth.len() == 0
}

// allocInitializedFrom returns true if receiver is a *ssa.Alloc whose sole initializing store
// writes val's value into it (the standard SSA pattern for spilling a by-value parameter to an
// addressable local slot, e.g. a struct parameter passed by value that needs FieldAddr access).
func allocInitializedFrom(receiver ssa.Value, val ssa.Value) bool {
	alloc, ok := receiver.(*ssa.Alloc)
	if !ok {
		return false
	}
	refs := alloc.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		if store, ok := ref.(*ssa.Store); ok && store.Addr == alloc && store.Val == val {
			return true
		}
	}
	return false
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
