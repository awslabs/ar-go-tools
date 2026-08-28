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
	"slices"

	"golang.org/x/tools/go/ssa"
)

// accessPathProvenanceFact identifies one field-sensitive fact from the forward lattice. The mark
// names the top-level source (parameter, free variable, call boundary, and so on); path names the
// region of value that currently carries that mark.
//
// The instruction is intentionally absent. SSA values already identify their defining statement,
// and mutable updates are represented by explicit propagation/store edges. Including every program
// point would duplicate the same unchanged fact across the CFG and defeat StubDroid's Section 5
// optimization, which records statements that influence a taint rather than every point it passes.
type accessPathProvenanceFact struct {
	value ssa.Value
	path  string
	mark  *Mark
}

// pathTransform describes the forward relationship between two access-path provenance facts.
// project removes a field/index prefix while moving into a subobject (x -> x.F); inject prepends a
// prefix while moving data into an aggregate (v -> x.F). Both may be set for a composed operation.
// coarse means field correspondence is unknown, so backward reconstruction must return the
// field-insensitive source path instead of guessing a precise relation.
type pathTransform struct {
	project string
	inject  string
	coarse  bool
}

// accessPathProvenanceEdge is one incoming derivation of an access-path provenance fact. from and
// transform are used for backward reconstruction; at identifies the influencing statement for
// diagnostics and keeps distinct assignments available when they derive the same destination fact.
type accessPathProvenanceEdge struct {
	from      accessPathProvenanceFact
	transform pathTransform
	at        ssa.Instruction
}

// identityTransform preserves field correspondence exactly.
func identityTransform() pathTransform { return pathTransform{} }

// coarseTransform preserves reachability but intentionally forgets field correspondence.
func coarseTransform() pathTransform { return pathTransform{coarse: true} }

// projectTransform records a read from a field/index below the source value.
func projectTransform(path string) pathTransform {
	return pathTransform{project: normalizeTransformPath(path)}
}

// injectTransform records a write into a field/index below the destination value.
func injectTransform(path string) pathTransform {
	return pathTransform{inject: normalizeTransformPath(path)}
}

// normalizeTransformPath accepts the legacy field-name form used by some transfer sites and
// converts it to the canonical separator-prefixed access-path form.
func normalizeTransformPath(path string) string {
	if path == "" || path == "*" || path[0] == '.' || path[0] == '[' {
		return path
	}
	return "." + path
}

// recordAccessPathProvenance records how one base-mark fact produced another without adding
// source-path variants to the forward lattice. It must run before the lattice's novelty check:
// after a join, a destination mark may already exist even though a newly encountered assignment
// provides another source path that the summary must include.
//
// This implements the key StubDroid Section 5 idea locally: propagate one abstract top-level input
// mark during analysis, record the path-changing statements separately, and recover concrete input
// fields by walking those statements backward only when materializing the summary. Functions that
// are field-insensitive cannot benefit from reconstruction, so their edges are not retained.
func (state *IntraAnalysisState) recordAccessPathProvenance(
	from, to accessPathProvenanceFact, transform pathTransform, at ssa.Instruction,
) {
	if state.eagerInputPaths || from.value == nil || to.value == nil || from.mark == nil || to.mark == nil {
		return
	}
	fromID, fromOK := state.flowInfo.ValueID[from.value]
	toID, toOK := state.flowInfo.ValueID[to.value]
	if !fromOK || !toOK || state.flowInfo.fieldLength[fromID] == 0 && state.flowInfo.fieldLength[toID] == 0 {
		return
	}
	if state.accessPathProvenance[to] == nil {
		state.accessPathProvenance[to] = make(map[accessPathProvenanceEdge]struct{})
	}
	state.accessPathProvenance[to][accessPathProvenanceEdge{from: from, transform: transform, at: at}] = struct{}{}
}

// makeAccessPathProvenanceFact constructs the compact identity used by the access-path provenance
// graph.
func makeAccessPathProvenanceFact(value ssa.Value, path string, mark *Mark) accessPathProvenanceFact {
	return accessPathProvenanceFact{value: value, path: path, mark: mark}
}

// accessPathProvenanceSourcePaths recovers the top-level input paths that can produce target at
// path. The traversal reverses recorded projections/injections until it reaches the value
// represented by the base mark. Its visited key includes the reconstructed path, so two fields
// reaching the same SSA value remain distinct while cycles still terminate at the configured bound.
//
// A coarse edge contributes the empty source path. Empty means “the whole input may influence this
// destination,” which is Argot's conservative representation when exact field correspondence is
// unavailable.
func (state *IntraAnalysisState) accessPathProvenanceSourcePaths(
	target accessPathProvenanceFact, path string,
) []string {
	type traversalState struct {
		fact accessPathProvenanceFact
		path string
	}
	work := []traversalState{{fact: target, path: path}}
	seen := make(map[traversalState]bool)
	found := make(map[string]bool)

	for len(work) > 0 {
		current := work[len(work)-1]
		work = work[:len(work)-1]
		if seen[current] {
			continue
		}
		seen[current] = true
		if isAccessPathProvenanceSource(current.fact) {
			found[current.path] = true
			continue
		}
		edges := state.accessPathProvenance[current.fact]
		if len(edges) == 0 {
			continue
		}
		for edge := range edges {
			predecessorPath, precise := invertPathTransform(current.path, edge.transform)
			if !precise {
				found[""] = true
				continue
			}
			work = append(work, traversalState{fact: edge.from, path: predecessorPath})
		}
	}

	paths := make([]string, 0, len(found))
	for path := range found {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// isAccessPathProvenanceSource reports whether a fact has reached the interface value that
// introduced its mark. Bound-variable and call-argument marks use Qualifier because their
// Mark.Node is the enclosing closure/call instruction itself.
func isAccessPathProvenanceSource(fact accessPathProvenanceFact) bool {
	mark := fact.mark
	source, ok := mark.Node.(ssa.Value)
	if !ok {
		return false
	}
	switch {
	case mark.IsParameter(), mark.IsFreeVar():
		return fact.value == source
	case mark.IsBoundVar(), mark.IsCallSiteArg():
		return fact.value == mark.Qualifier
	case mark.IsCallReturn(), mark.IsClosure(), mark.IsSynthetic(), mark.IsGlobal(), mark.IsDefault():
		return fact.value == source
	}
	return false
}

// invertPathTransform maps a destination-relative path back to its predecessor-relative path.
// Injection is undone first because forward propagation projects from the source before injecting
// into the destination. A false result requires the caller to add a field-insensitive source flow.
func invertPathTransform(path string, transform pathTransform) (string, bool) {
	if transform.coarse {
		return "", false
	}
	if transform.inject != "" {
		var ok bool
		path, ok = accessPathCutPrefix(path, transform.inject)
		if !ok {
			return "", false
		}
	}
	if transform.project != "" {
		path = appendAccessPaths(transform.project, path)
	}
	return path, true
}
