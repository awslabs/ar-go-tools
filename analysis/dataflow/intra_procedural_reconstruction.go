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

package dataflow

import (
	"go/token"
	"slices"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/ssa"
)

// reconstructionQuery identifies one summary-boundary request. Results are immutable after the
// forward fixpoint, so caching by instruction, value, and requested path is safe.
type reconstructionQuery struct {
	instr      ssa.Instruction
	value      ssa.Value
	path       string
	ignorePath bool
}

// reconstructionState is a state in the committed SSA-based backward oracle. instr is required
// because mutable values can carry different marks before and after a store; path is the region of
// value currently being traced toward the mark's source.
type reconstructionState struct {
	instr ssa.Instruction
	value ssa.Value
	path  string
}

// reconstructedOrigin is the final relation consumed by SummaryGraph edge construction. mark
// identifies the top-level interface source, while sourcePath and destinationPath describe the
// bounded regions below the source and destination nodes.
type reconstructedOrigin struct {
	mark            *Mark
	sourcePath      string
	destinationPath string
}

// reconstructMarks recovers input access paths after the forward fixpoint. It never mutates the
// abstract state; unsupported memory or SSA shapes conservatively produce a field-insensitive path.
//
// Compact access-path provenance supplies the normal result. The SSA walk is retained as a
// soundness oracle during migration, and the two path sets are unioned so incomplete access-path
// provenance cannot remove a flow. Labelled marks created here are used only to serialize
// SummaryGraph edges and never re-enter flowInfo.
func (state *IntraAnalysisState) reconstructMarks(
	instr ssa.Instruction, value ssa.Value, path string, ignorePath bool,
) []MarkWithAccessPath {
	query := reconstructionQuery{instr: instr, value: value, path: path, ignorePath: ignorePath}
	if cached, ok := state.reconstructionCache[query]; ok {
		return slices.Clone(cached)
	}

	abstractValue := state.abstractValueAt(instr, value)
	if abstractValue == nil {
		return nil
	}

	var reconstructed []reconstructedOrigin
	seenOrigins := make(map[reconstructedOrigin]bool)
	for storedPath, marks := range abstractValue.PathMappings() {
		for mark := range marks {
			for _, candidatePath := range state.reconstructionCandidatePaths(
				value, storedPath, path, ignorePath,
			) {
				startPath, destinationPath, ok := reconstructionPaths(
					candidatePath, path, ignorePath,
				)
				if !ok {
					continue
				}
				sourcePaths := state.accessPathProvenanceSourcePaths(
					makeAccessPathProvenanceFact(value, storedPath, mark), startPath,
				)
				if mark.IsCallReturn() && storedPath == "" {
					// A base call-return mark denotes the entire returned object. Keep the whole-value
					// relation even when field-specific uses also reconstruct more precise paths.
					sourcePaths = unionSourcePaths(sourcePaths, []string{""})
				}
				if state.summary.Parent.Synthetic != "" || mark.IsBoundVar() {
					// Synthetic wrappers and bound-variable boundaries preserve the selected captured
					// subobject while adapting its callable representation.
					sourcePaths = unionSourcePaths(sourcePaths, []string{startPath})
				}
				if mark.IsClosure() {
					// The closure mark denotes the captured callable value. Preserve a path already
					// stored on that value, and also relocate through an explicit field-address chain
					// when the current SSA value names one.
					sourcePaths = unionSourcePaths(sourcePaths, []string{startPath})
					_, closurePath := addressRootPath(value)
					if closurePath != "" {
						sourcePaths = unionSourcePaths(
							sourcePaths, []string{appendAccessPaths(closurePath, startPath)},
						)
					}
				}
				oraclePaths := state.backwardSourcePaths(instr, value, startPath, mark)
				sourcePaths = unionSourcePaths(sourcePaths, oraclePaths)
				if len(sourcePaths) == 0 {
					// The forward fixpoint proved reachability, so failure to invert an operation must
					// degrade precision rather than discard the flow.
					sourcePaths = []string{""}
					destinationPath = ""
				}
				for _, sourcePath := range sourcePaths {
					origin := reconstructedOrigin{
						mark:            mark,
						sourcePath:      sourcePath,
						destinationPath: destinationPath,
					}
					if !seenOrigins[origin] {
						reconstructed = append(reconstructed, origin)
						seenOrigins[origin] = true
					}
				}
			}
		}
	}

	result := make([]MarkWithAccessPath, 0, len(reconstructed))
	for _, origin := range reconstructed {
		mark := origin.mark
		if origin.sourcePath != mark.Label {
			mark = state.flowInfo.GetNewLabelledMark(
				mark.Node, mark.Type, mark.Qualifier, mark.Index, origin.sourcePath,
			)
		}
		result = append(result, MarkWithAccessPath{Mark: mark, AccessPath: origin.destinationPath})
	}
	state.reconstructionCache[query] = slices.Clone(result)
	return result
}

// unionSourcePaths combines access-path provenance and oracle results without assigning meaning
// to order.
func unionSourcePaths(left, right []string) []string {
	seen := make(map[string]bool, len(left)+len(right))
	for _, path := range left {
		seen[path] = true
	}
	for _, path := range right {
		seen[path] = true
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// reconstructionCandidatePaths expands a root fact only at a summary boundary. This preserves the
// common suffix represented by StubDroid's rules such as src.prefix.* -> dst.prefix.* without
// carrying one source-labelled mark per leaf through the fixpoint. Existing non-root facts and
// explicit queries already provide their required precision and are returned unchanged.
func (state *IntraAnalysisState) reconstructionCandidatePaths(
	value ssa.Value, storedPath, queryPath string, ignorePath bool,
) []string {
	if storedPath != "" || queryPath != "" && !ignorePath || value == nil || !lang.CanType(value) {
		return []string{storedPath}
	}
	depth := state.flowInfo.fieldLength[state.flowInfo.ValueID[value]]
	if depth == 0 {
		return []string{""}
	}
	paths := AccessPathsOfType(value.Type(), depth)
	if len(paths) == 0 {
		return []string{""}
	}
	return paths
}

// reconstructionPaths applies a sink's query to one stored path. The returned start path is traced
// toward the source; destinationPath is the unconsumed suffix stored on the SummaryGraph edge.
func reconstructionPaths(storedPath, queryPath string, ignorePath bool) (string, string, bool) {
	if ignorePath || queryPath == "" {
		return storedPath, storedPath, true
	}
	if storedPath == "" {
		return queryPath, "", true
	}
	remainder, ok := accessPathCutPrefix(storedPath, queryPath)
	if !ok {
		return "", "", false
	}
	return storedPath, remainder, true
}

// abstractValueAt returns the converged lattice value for one SSA value at one instruction.
func (state *IntraAnalysisState) abstractValueAt(
	instr ssa.Instruction, value ssa.Value,
) *AbstractValue {
	pos, ok := state.flowInfo.GetPos(instr, value)
	if !ok {
		return nil
	}
	return state.flowInfo.MarkedValues[pos]
}

// backwardSourcePaths is the SSA-based reconstruction oracle used while access-path provenance
// coverage is being validated. It follows the same instrPrev relation used by the forward merge, reverses SSA definitions, and
// considers every may-alias reaching store. Including path in the visited state preserves sibling
// derivations while bounding loops. An operation whose inverse is unknown contributes the empty
// source path, never the absence of a flow.
func (state *IntraAnalysisState) backwardSourcePaths(
	instr ssa.Instruction, value ssa.Value, path string, mark *Mark,
) []string {
	work := []reconstructionState{{instr: instr, value: value, path: path}}
	seen := make(map[reconstructionState]bool)
	found := make(map[string]bool)
	coarse := false

	for len(work) > 0 {
		current := work[len(work)-1]
		work = work[:len(work)-1]
		if current.instr == nil || current.value == nil || seen[current] {
			continue
		}
		seen[current] = true
		if !state.markAt(current.instr, current.value, current.path, mark) {
			continue
		}

		if state.isMarkSource(current, mark) {
			found[current.path] = true
			continue
		}

		// Follow the same SSA value across the predecessor relation used by Pre. This preserves
		// alternate CFG paths while the visited set bounds loops.
		for predecessorID := range state.instrPrev[state.flowInfo.InstrID[current.instr]] {
			predecessor := state.instructionByID(predecessorID)
			if predecessor != nil && state.markAt(predecessor, current.value, current.path, mark) {
				work = append(work, reconstructionState{
					instr: predecessor, value: current.value, path: current.path,
				})
			}
		}

		if defining, ok := current.value.(ssa.Instruction); ok && defining == current.instr {
			predecessors, precise := state.invertSSAValue(defining, current.path, mark)
			work = append(work, predecessors...)
			coarse = coarse || !precise
		}

		if store, ok := current.instr.(*ssa.Store); ok {
			if valuePath, ok := state.storeWritesValuePath(store, current.value, current.path); ok &&
				state.markAt(store, store.Val, valuePath, mark) {
				work = append(work, reconstructionState{
					instr: store, value: store.Val, path: valuePath,
				})
			}
		}
	}

	if coarse {
		found[""] = true
	}
	paths := make([]string, 0, len(found))
	for path := range found {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// markAt asks the converged lattice whether mark covers path on value at instr. A root lattice path
// covers every queried subpath, matching the “taint subfields” meaning of a base input mark.
func (state *IntraAnalysisState) markAt(
	instr ssa.Instruction, value ssa.Value, path string, mark *Mark,
) bool {
	_, present := state.flowInfo.HasMarkAt(instr, value, path, mark)
	return present
}

// isMarkSource reports whether the oracle has reached the interface value that introduced mark.
// Call arguments use Qualifier because their Mark.Node is the enclosing call instruction.
func (state *IntraAnalysisState) isMarkSource(current reconstructionState, mark *Mark) bool {
	sourceValue, sourceIsValue := mark.Node.(ssa.Value)
	sourceInstr, sourceIsInstr := mark.Node.(ssa.Instruction)
	switch {
	case mark.IsParameter(), mark.IsFreeVar():
		return sourceIsValue && current.value == sourceValue
	case mark.IsCallSiteArg():
		return sourceIsInstr && current.instr == sourceInstr && current.value == mark.Qualifier
	case mark.IsCallReturn():
		return sourceIsInstr && sourceIsValue && current.instr == sourceInstr && current.value == sourceValue
	case mark.IsClosure(), mark.IsBoundVar(), mark.IsSynthetic(), mark.IsGlobal(), mark.IsDefault():
		return sourceIsValue && current.value == sourceValue || sourceIsInstr && current.instr == sourceInstr
	}
	return false
}

// indexReconstructionInstructions builds compact lookup tables once per analyzed function. Store
// indexing avoids rescanning every SSA instruction for each backward load or mutated output.
func (state *IntraAnalysisState) indexReconstructionInstructions() {
	state.instructionsByID = make([]ssa.Instruction, state.flowInfo.NumInstructions)
	lang.IterateInstructions(state.summary.Parent, func(_ int, instr ssa.Instruction) {
		id, ok := state.flowInfo.InstrID[instr]
		if !ok {
			return
		}
		state.instructionsByID[id] = instr
		if store, ok := instr.(*ssa.Store); ok {
			state.stores = append(state.stores, store)
		}
	})
}

// instructionByID resolves the IDs used by instrPrev without a map scan during every oracle step.
func (state *IntraAnalysisState) instructionByID(id IndexT) ssa.Instruction {
	if int(id) >= len(state.instructionsByID) {
		return nil
	}
	return state.instructionsByID[id]
}

// invertSSAValue returns feasible predecessor states for a value-producing SSA instruction. The
// boolean states whether field correspondence is exact; false requires a coarse source flow even
// when some operands can still be followed precisely.
func (state *IntraAnalysisState) invertSSAValue(
	value ssa.Instruction, path string, mark *Mark,
) ([]reconstructionState, bool) {
	add := func(result []reconstructionState, operand ssa.Value, operandPath string) []reconstructionState {
		if operand != nil && state.markAt(value, operand, operandPath, mark) {
			result = append(result, reconstructionState{instr: value, value: operand, path: operandPath})
		}
		return result
	}

	var result []reconstructionState
	switch x := value.(type) {
	case *ssa.Field:
		field := analysisutil.FieldFieldInfo(x)
		return add(result, x.X, accessPathPrependField(path, field.FieldName, field.IsEmbedded)), true
	case *ssa.FieldAddr:
		field := analysisutil.FieldAddrFieldInfo(x)
		return add(result, x.X, accessPathPrependField(path, field.FieldName, field.IsEmbedded)), true
	case *ssa.Index:
		return add(result, x.X, accessPathPrependIndexing(path)), true
	case *ssa.IndexAddr:
		return add(result, x.X, accessPathPrependIndexing(path)), true
	case *ssa.UnOp:
		result = add(result, x.X, path)
		if x.Op == token.MUL {
			result = append(result, state.reachingStores(x, x.X, path, mark)...)
		}
		return result, true
	case *ssa.ChangeInterface:
		return add(result, x.X, path), true
	case *ssa.ChangeType:
		return add(result, x.X, path), true
	case *ssa.Convert:
		return add(result, x.X, path), true
	case *ssa.SliceToArrayPointer:
		return add(result, x.X, path), true
	case *ssa.MakeInterface:
		return add(result, x.X, path), true
	case *ssa.Slice:
		return add(result, x.X, path), true
	case *ssa.Extract:
		return add(result, x.Tuple, path), true
	case *ssa.Phi:
		for _, edge := range x.Edges {
			result = add(result, edge, path)
		}
		return result, true
	case *ssa.BinOp:
		result = add(result, x.X, "")
		result = add(result, x.Y, "")
		return result, path == ""
	case *ssa.Lookup:
		result = add(result, x.X, accessPathPrependIndexing(path))
		result = add(result, x.Index, "")
		return result, true
	case *ssa.Next:
		return add(result, x.Iter, accessPathPrependIndexing(path)), true
	case *ssa.Range:
		return add(result, x.X, path), true
	case *ssa.Call:
		if mark.IsCallReturn() && mark.Node == x {
			return result, true
		}
	}

	// Unknown value-producing operations are still traversed through all operands, but their path
	// relation is deliberately forgotten.
	var operands []*ssa.Value
	operands = value.Operands(operands)
	for _, operand := range operands {
		if operand != nil {
			result = add(result, *operand, "")
		}
	}
	return result, false
}

// reachingStores finds every store that may supply a dereference. Pointer analysis supplies a
// sound may-alias set; CFG reachability removes stores that cannot precede the load. Extra stores
// may reduce precision but cannot remove a real flow.
func (state *IntraAnalysisState) reachingStores(
	load ssa.Instruction, address ssa.Value, path string, mark *Mark,
) []reconstructionState {
	var stores []reconstructionState
	for _, store := range state.stores {
		if !state.checkPathBetweenInstructions(store, load).Satisfiable {
			continue
		}
		if valuePath, ok := state.storeAddressMatches(store.Addr, address, path); ok &&
			state.markAt(store, store.Val, valuePath, mark) {
			stores = append(stores, reconstructionState{
				instr: store, value: store.Val, path: valuePath,
			})
		}
	}
	return stores
}

// storeWritesValuePath maps a path on an aliased destination value to the corresponding path on
// the value written by store.
func (state *IntraAnalysisState) storeWritesValuePath(
	store *ssa.Store, value ssa.Value, path string,
) (string, bool) {
	return state.storeAddressMatches(store.Addr, value, path)
}

// storeAddressMatches checks both aliasing and subobject position. A store through &x.F can supply
// only a queried path beginning with .F; the returned remainder is the path on the stored value.
func (state *IntraAnalysisState) storeAddressMatches(
	address, value ssa.Value, path string,
) (string, bool) {
	root, addressPath := addressRootPath(address)
	if !state.valuesMayAlias(root, value) {
		return "", false
	}
	if addressPath == "" {
		return path, true
	}
	remainder, ok := accessPathCutPrefix(path, addressPath)
	return remainder, ok
}

// addressRootPath peels field/index addresses and dereferences to recover an aggregate root and
// the path addressed below it. Embedded fields are omitted because Argot access paths omit them.
func addressRootPath(value ssa.Value) (ssa.Value, string) {
	var reversed []string
	for {
		switch x := value.(type) {
		case *ssa.FieldAddr:
			field := analysisutil.FieldAddrFieldInfo(x)
			if !field.IsEmbedded {
				reversed = append(reversed, "."+field.FieldName)
			}
			value = x.X
		case *ssa.IndexAddr:
			reversed = append(reversed, "[*]")
			value = x.X
		case *ssa.UnOp:
			if x.Op != token.MUL {
				path := ""
				for i := len(reversed) - 1; i >= 0; i-- {
					path += reversed[i]
				}
				return value, path
			}
			value = x.X
		default:
			path := ""
			for i := len(reversed) - 1; i >= 0; i-- {
				path += reversed[i]
			}
			return value, path
		}
	}
}

// containerRootPath recognizes values produced from map/slice iteration or lookup. Such an element
// does not pointer-alias the container value itself, so callers use the returned [*] relationship
// and add a coarse fallback when materializing container mutations.
func containerRootPath(value ssa.Value) (ssa.Value, string, bool) {
	switch x := value.(type) {
	case *ssa.Extract:
		return containerRootPath(x.Tuple)
	case *ssa.Next:
		return containerRootPath(x.Iter)
	case *ssa.Range:
		return x.X, "[*]", true
	case *ssa.Lookup:
		return x.X, "[*]", true
	case *ssa.Index:
		return x.X, "[*]", true
	case *ssa.IndexAddr:
		return x.X, "[*]", true
	}
	return nil, "", false
}

// valuesMayAlias uses both direct and indirect pointer queries. False excludes an edge; true only
// establishes a possible relationship, so callers must not infer stronger offset equality from it.
func (state *IntraAnalysisState) valuesMayAlias(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	for _, left := range state.findAllPointers(a) {
		for _, right := range state.findAllPointers(b) {
			if left.MayAlias(right) {
				return true
			}
		}
	}
	return false
}

// aliasDestinationPath relocates a reconstructed path from an aliased SSA address to the parameter
// or free-variable root used by the summary interface.
func (state *IntraAnalysisState) aliasDestinationPath(
	value, destination ssa.Value, path string,
) string {
	root, aliasPath := addressRootPath(value)
	if aliasPath == "" || !state.valuesMayAlias(root, destination) {
		return path
	}
	return appendAccessPaths(aliasPath, path)
}

// appendAccessPaths composes two paths and truncates at the analysis bound. The truncated path
// denotes the entire subtree below that frontier rather than discarding deeper flows.
func appendAccessPaths(prefix, suffix string) string {
	path := prefix + suffix
	for accessPathLen(path) > maxAccessPathLength+1 {
		path = pathTrimLast(path)
	}
	return path
}

// materializeStoreOutputEdges recovers field-to-field mutations that a base-mark set cannot
// represent when the source and destination belong to the same parameter/free variable.
//
// A whole-input base mark already covers every subpath in the lattice, so writing that mark into a
// different field is not a novel lattice fact. Reaching stores are therefore inspected at returns.
// Map/range elements use membership rather than direct pointer aliasing, so their precise [*] edge
// is accompanied by a field-insensitive fallback.
func (state *IntraAnalysisState) materializeStoreOutputEdges(ret *ssa.Return) {
	for _, store := range state.stores {
		if !state.checkPathBetweenInstructions(store, ret).Satisfiable {
			continue
		}
		root, destinationPath := addressRootPath(store.Addr)
		containerRelation := false
		if container, containerPath, ok := containerRootPath(root); ok {
			root = container
			destinationPath = appendAccessPaths(containerPath, destinationPath)
			containerRelation = true
		}
		if destinationPath == "" {
			continue
		}
		for _, origin := range state.getMarks(store, store.Val, "", true) {
			for _, parameter := range state.summary.Parent.Params {
				if !lang.IsNillableType(parameter.Type()) || !state.valuesMayAlias(root, parameter) {
					continue
				}
				adjusted := origin
				adjusted.AccessPath = appendAccessPaths(destinationPath, origin.AccessPath)
				state.summary.addParamEdge(adjusted, nil, parameter)
				if containerRelation {
					coarse := origin
					coarse.AccessPath = ""
					state.summary.addParamEdge(coarse, nil, parameter)
				}
			}
			for _, freeVar := range state.summary.Parent.FreeVars {
				if !lang.IsNillableType(freeVar.Type()) || !state.valuesMayAlias(root, freeVar) {
					continue
				}
				adjusted := origin
				adjusted.AccessPath = appendAccessPaths(destinationPath, origin.AccessPath)
				state.summary.addFreeVarEdge(adjusted, nil, freeVar)
				if containerRelation {
					coarse := origin
					coarse.AccessPath = ""
					state.summary.addFreeVarEdge(coarse, nil, freeVar)
				}
			}
		}
	}
}
