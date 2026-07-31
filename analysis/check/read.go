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

	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
)

// readCacheEntry caches the result of checkReads for a given (value, path): whether it was read,
// and if so, the instruction that reads it (used for logging on a cache hit).
type readCacheEntry struct {
	wasRead bool
	instr   readInstr
}

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
		key := value{val, fl.from.path}
		cached, ok := s.readCache[key]
		if !ok {
			ri, wasRead, err := checkReads(ctx, s, val, fl.from.path)
			if err != nil {
				return false, fmt.Errorf(
					"failed to check reads from flow input value %v: %w", val, err)
			}
			cached = readCacheEntry{wasRead: wasRead, instr: ri}
			s.readCache[key] = cached
		}

		if cached.wasRead {
			s.Logger.Tracef(
				"found access of flow input value %v with path %q in must-not-flow %v: read %v at %s\n",
				val, fl, fl.to.path, cached.instr, s.Program.Fset.Position(cached.instr.Pos()))
			return false, nil
		}
	}

	return true, nil
}

// checkReads returns an instruction that reads from val's memory at path pth, searching val's
// enclosing function and its callees in BFS order. A false result means no read was found.
//
// Three matchers are tried per instruction, and any one matching is enough: matchesWholeValueRead,
// matchesViaFieldChain and matchesViaPointsTo. None is complete for every SSA shape on its own, and
// none may be treated as authoritative when it returns false.
//
//gocyclo:ignore
func checkReads(ctx context.Context, s *State, val ssa.Value, pth path) (readInstr, bool, error) {
	cg := s.PointerAnalysis.CallGraph
	start := cg.Nodes[val.Parent()]
	if start == nil {
		return readInstr{}, false, fmt.Errorf(
			"no call graph node for %s, the parent of %v; conservatively treating it as read\n",
			val.Parent(), val)
	}

	queue := []*callgraph.Node{start}
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

	// If the pointer analysis knows nothing about val, track it field-insensitively: any read of the
	// value counts as a read of every path within it.
	if ids.IsEmpty() && len(s.cache.Labels(val)) == 0 {
		if pth.len() > 0 {
			s.Logger.Tracef(
				"  no points-to information for %v; tracking it field-insensitively instead of %v\n",
				val, pth)
		}
		pth = path{}
	}

	for len(queue) > 0 {
		// This function can take a while so handle timeouts
		select {
		case <-ctx.Done():
			return readInstr{}, false, ctx.Err()
		default:
		}

		node := queue[0]
		queue = queue[1:]
		if node == nil {
			continue
		}
		if _, ok := seen[node]; ok {
			continue
		}
		seen[node] = struct{}{}
		if node.Func == nil {
			// Synthetic node with no body. Skip it and keep searching: returning here would abandon
			// the search and report the value as unread, proving every must-not-flow out of it.
			continue
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

			if matchesWholeValueRead(instr, val, pth, read) {
				wasRead = true
				res = read
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

// matchesWholeValueRead reports whether instr reads a region of val that overlaps pth: val itself, or
// a sub-struct of it at some prefix of pth.
//
// Overlap in either direction counts. Reading c.Src reads everything under it, so it matches
// pth = .Src.X; reading c.Dst.X matches neither .Src.X nor .Dst, since a read of one field says
// nothing about a sibling and reading a leaf is not reading its parent.
//
// Two shapes are excluded because for them read.values holds the *receiver* of a field access rather
// than the region read, so containment would treat every field access as reading the whole object:
//   - *ssa.Field and *ssa.FieldAddr, which are field-granular and are matchesViaFieldChain's job.
//   - the parameter spill `*alloc = val`, while val is tracked field-sensitively: it only copies val
//     into a local slot, so which fields are really read is decided by what reads that slot
//     afterwards. Counting the spill would make no field of any addressed by-value struct parameter
//     provable. When val is field-insensitive there is nothing to lose, and counting it avoids
//     depending on allocInitializedFrom recognizing the slot.
func matchesWholeValueRead(instr ssa.Instruction, val ssa.Value, pth path, read readInstr) bool {
	switch instr.(type) {
	case *ssa.Field, *ssa.FieldAddr:
		return false
	}
	if st, ok := instr.(*ssa.Store); ok && pth.len() > 0 && allocInitializedFrom(st.Addr, val) {
		return false
	}
	for _, rval := range read.values {
		region, ok := fieldChainPathTo(rval, val)
		if !ok {
			continue
		}
		// region overlaps pth: reading either contains or is contained by the queried path, and in
		// both directions memory belonging to pth was read.
		if pathsOverlap(region, pth) {
			return true
		}
	}
	return false
}

// fieldChainPathTo returns the access path into val that v denotes, if v is a chain of field
// accesses (possibly through dereferences) bottoming out at val or at val's spill slot. The empty
// path means v denotes all of val.
func fieldChainPathTo(v ssa.Value, val ssa.Value) (path, bool) {
	var rev []string
	// A chain longer than the access paths we track cannot match one, and the bound also guarantees
	// termination.
	for range maxPathLen + 2 {
		if v == val || allocInitializedFrom(v, val) {
			if len(rev) > maxPathLen {
				return path{}, false
			}
			var p path
			for i := range rev {
				p[i] = rev[len(rev)-1-i]
			}
			return p, true
		}
		switch x := v.(type) {
		case *ssa.UnOp:
			if x.Op != token.MUL {
				return path{}, false
			}
			v = x.X
		case *ssa.Field:
			rev = append(rev, analysisutil.FieldFieldInfo(x).FieldName)
			v = x.X
		case *ssa.FieldAddr:
			rev = append(rev, analysisutil.FieldAddrFieldInfo(x).FieldName)
			v = x.X
		default:
			return path{}, false
		}
	}
	return path{}, false
}

// matchesViaFieldChain reports whether instr reads (val, pth) based purely on SSA field-access
// structure, without the pointer analysis. Needed because non-escaping stack values have no
// points-to information at all.
//
// Each *ssa.Field / *ssa.FieldAddr addresses exactly one field, so walking the chain of nested
// accesses back to val gives an exact answer, including for pth.len() > 1 and for by-value struct
// parameters spilled to a local *ssa.Alloc.
//
// A false result does not prove instr irrelevant -- the walk does not understand every SSA shape,
// such as aliasing through calls -- so callers must still try matchesViaPointsTo.
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

// matchesViaPointsTo reports whether read reads (val, pth), using val's points-to ids to decide
// aliasing that matchesViaFieldChain's structural walk cannot, such as aliasing through calls.
//
// It finds nothing for values with no points-to information, notably non-escaping stack locals.
func matchesViaPointsTo(s *State, val ssa.Value, ids *intsets.Sparse, pth path, read readInstr) bool {
	for _, rval := range read.values {
		if rval == val {
			if pth.len() == 0 {
				return true
			}

			// The operand is val directly, so the field named here is decisive. A mismatch skips
			// the instruction rather than falling through to the mlabels check, which would match
			// any sibling field of the same object (&c.Body must not count as touching
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

// valsReadFrom returns the non-nil values read from instr.
//
// Values come from instr.Operands rather than a per-kind switch, so the set is complete by
// construction: an unenumerated instruction kind still yields its reads. This matters because a
// missing kind makes flows out of its operands provably absent, which is the unsafe direction.
//
// The cases below are the operands that are write destinations rather than reads.
func valsReadFrom(instr ssa.Instruction) (readInstr, bool) {
	var rvals []ssa.Value
	switch instr := instr.(type) {
	case *ssa.DebugRef:
		// Debug metadata, not a semantic operation.

	case *ssa.Store:
		// *Addr = Val writes through Addr, so only Val is read. Addr's own value (the pointer) is
		// not what the flow is about: writes to the pointed-to memory are the immutability check's
		// concern, not Read's.
		rvals = nonNilVals(instr.Val)

	case *ssa.MapUpdate:
		// Map[Key] = Value writes into Map.
		rvals = nonNilVals(instr.Key, instr.Value)

	case *ssa.FieldAddr:
		// &X.f only computes an address; it reads X only if that address is ever dereferenced for
		// its value rather than used purely as a write destination.
		if fieldAddrIsDereferenced(instr) {
			rvals = nonNilVals(instr.X)
		}

	default:
		rvals = operandVals(instr)
	}

	if len(rvals) == 0 {
		return readInstr{Instruction: instr, values: nil}, false
	}
	return readInstr{Instruction: instr, values: rvals}, true
}

// nonNilVals returns vs without its nil entries.
func nonNilVals(vs ...ssa.Value) []ssa.Value {
	var out []ssa.Value
	for _, v := range vs {
		if v != nil {
			out = append(out, v)
		}
	}
	return out
}

// operandVals returns every non-nil Value instr references.
func operandVals(instr ssa.Instruction) []ssa.Value {
	var out []ssa.Value
	for _, p := range instr.Operands(nil) {
		if p == nil || *p == nil {
			continue
		}
		out = append(out, *p)
	}
	return out
}

// fieldAddrIsDereferenced reports whether &x.Field is ever dereferenced for its value, as opposed to
// being used only as a write destination.
//
// Computing a field's address is not a read of it: `t1 = &x.Body` followed only by `*t1 = v` writes
// x.Body without reading the value it held before.
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
			if ref.Val == instr {
				// `*out = &x.Field` lets the address escape, so it may be dereferenced later out of
				// sight of this local walk.
				return true
			}
			// *t1 = v writes through t1 rather than reading it.
			continue
		case *ssa.FieldAddr:
			// &(&x.Field).Nested navigates through the outer address; a read only if the nested
			// access is itself dereferenced.
			if fieldAddrIsDereferenced(ref) {
				return true
			}
		default:
			// Any other use (call argument, returned, stored elsewhere) may lead to a read we do not
			// track locally.
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
