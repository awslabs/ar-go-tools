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

type reconstructionQuery struct {
	instr      ssa.Instruction
	value      ssa.Value
	path       string
	ignorePath bool
}

type reconstructionState struct {
	instr ssa.Instruction
	value ssa.Value
	path  string
}

type reconstructedOrigin struct {
	mark            *Mark
	sourcePath      string
	destinationPath string
}

// reconstructMarks recovers input access paths after the forward fixpoint. It never mutates the
// abstract state; unsupported memory or SSA shapes conservatively produce a field-insensitive path.
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
				sourcePaths := state.backwardSourcePaths(instr, value, startPath, mark)
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

func (state *IntraAnalysisState) abstractValueAt(
	instr ssa.Instruction, value ssa.Value,
) *AbstractValue {
	pos, ok := state.flowInfo.GetPos(instr, value)
	if !ok {
		return nil
	}
	return state.flowInfo.MarkedValues[pos]
}

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

func (state *IntraAnalysisState) markAt(
	instr ssa.Instruction, value ssa.Value, path string, mark *Mark,
) bool {
	_, present := state.flowInfo.HasMarkAt(instr, value, path, mark)
	return present
}

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

func (state *IntraAnalysisState) instructionByID(id IndexT) ssa.Instruction {
	if int(id) >= len(state.instructionsByID) {
		return nil
	}
	return state.instructionsByID[id]
}

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

func (state *IntraAnalysisState) storeWritesValuePath(
	store *ssa.Store, value ssa.Value, path string,
) (string, bool) {
	return state.storeAddressMatches(store.Addr, value, path)
}

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

func (state *IntraAnalysisState) aliasDestinationPath(
	value, destination ssa.Value, path string,
) string {
	root, aliasPath := addressRootPath(value)
	if aliasPath == "" || !state.valuesMayAlias(root, destination) {
		return path
	}
	return appendAccessPaths(aliasPath, path)
}

func appendAccessPaths(prefix, suffix string) string {
	path := prefix + suffix
	for accessPathLen(path) > maxAccessPathLength+1 {
		path = pathTrimLast(path)
	}
	return path
}

// materializeStoreOutputEdges recovers field-to-field mutations that a base-mark set cannot
// represent when the source and destination belong to the same parameter/free variable.
func (state *IntraAnalysisState) materializeStoreOutputEdges(ret *ssa.Return) {
	for _, store := range state.stores {
		if !state.checkPathBetweenInstructions(store, ret).Satisfiable {
			continue
		}
		root, destinationPath := addressRootPath(store.Addr)
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
			}
			for _, freeVar := range state.summary.Parent.FreeVars {
				if !lang.IsNillableType(freeVar.Type()) || !state.valuesMayAlias(root, freeVar) {
					continue
				}
				adjusted := origin
				adjusted.AccessPath = appendAccessPaths(destinationPath, origin.AccessPath)
				state.summary.addFreeVarEdge(adjusted, nil, freeVar)
			}
		}
	}
}
