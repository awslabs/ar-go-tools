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
	"fmt"

	"github.com/crillab/gophersat/maxsat"
	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

// findSubspecs infers the most restrictive valid dataflow summary for callees
// using a pure MaxSAT encoding.
// It returns the must-not-flow edges needed to satisfy wantSummary.
//
// Encoding structure:
// 1. Variables: reach(a,b) for each potential dataflow edge a→b
// 2. Hard clauses (must be satisfied):
//   - Unit clauses: reach(a,b) for known edges
//   - Ternary clauses: ¬reach(a,b) ∨ ¬reach(b,c) ∨ reach(a,c) for transitivity
//   - Unit clauses: reach(a,b) for required summary edges
//   - Negative unit clauses: ¬reach(a,b) for forbidden summary edges
//   - Path existence via Tseitin transformation
//
// 3. Soft clauses (maximize satisfied):
//   - ¬reach(a,b) for each unknown edge (weight=1)
//
// The solver maximizes must-not-flow edges (minimizes dataflow) while
// satisfying all hard constraints.
//
// TODO return may-flow instead of must-not-flow
// Goal is to output a summary which we check recursively
func findSubspecs(s *dataflow.State, g *dataflow.SummaryGraph, wantSummary summaries.FrontendDataflowSummary) []edge {
	// Collect known (intra + inter) and unknown edges
	var known, unknown []edge

	intraParent := intraEdgesNonSummary(g)
	inter := interEdges(s, g)

	known = append(intraParent, inter...)

	allCallees := transitiveCallees(s.PointerAnalysis.CallGraph, g.Parent)
	for _, callee := range allCallees {
		// Skip the parent function itself
		if callee == g.Parent {
			continue
		}
		calleeG, ok := s.FlowGraph.Summaries[callee]
		if !ok {
			panic(fmt.Errorf("no summary for callee %s", callee))
		}
		// For callees, collect unknown edges (all possible intra-procedural edges)
		edges := unknownEdges(s, calleeG)
		for _, e := range edges {
			unknown = append(unknown, e)
		}
	}

	// Build MaxSAT problem
	var constraints []maxsat.Constr

	// === HARD CLAUSES ===

	// Known edges: unit clauses reach(a,b)
	for _, e := range known {
		constraints = append(constraints, maxsat.HardClause(reach(e.from, e.to)))
	}

	// Collect all nodes
	allNodes := make(map[dataflow.GraphNode]struct{})
	for _, e := range append(known, unknown...) {
		allNodes[e.from] = struct{}{}
		allNodes[e.to] = struct{}{}
	}

	// Hard: transitivity (reach(a,b) ∧ reach(b,c)) → reach(a,c)
	// Converted to CNF: ¬reach(a,b) ∨ ¬reach(b,c) ∨ reach(a,c)
	for _, abc := range permutations(maps.Keys(allNodes), 3) {
		a, b, c := abc[0], abc[1], abc[2]
		constraints = append(constraints,
			maxsat.HardClause(
				reach(a, b).Negation(),
				reach(b, c).Negation(),
				reach(a, c),
			))
	}

	// Required summary edges: unit clauses reach(a,b)
	// Forbidden summary edges: negative unit clauses ¬reach(a,b)
	wantFlows := wantSummary.Summary().Flows
	fNodes := collectFunctionNodes(g)

	for from, tos := range wantFlows {
		fromNode := findNodeByName(fNodes, from.String())
		for _, to := range tos {
			toNode := findNodeByName(fNodes, to.String())
			if fromNode != nil && toNode != nil {
				constraints = append(constraints, maxsat.HardClause(reach(fromNode, toNode)))
			}
		}
	}
	// Forbid all other f-node pairs
	for _, from := range fNodes {
		for _, to := range fNodes {
			if from.String() != to.String() && !hasFlow(wantFlows, from, to) {
				constraints = append(constraints, maxsat.HardClause(reach(from, to).Negation()))
			}
		}
	}

	// Path existence constraints using Tseitin transformation
	pathIdx := 0
	for from, tos := range wantFlows {
		fromNode := findNodeByName(fNodes, from.String())
		for _, to := range tos {
			toNode := findNodeByName(fNodes, to.String())
			if fromNode != nil && toNode != nil {
				paths := findPathsThroughUnknown(fromNode, toNode, known, unknown)
				if len(paths) > 0 {
					var pathVars []maxsat.Lit
					for _, pathEdges := range paths {
						if len(pathEdges) > 0 {
							pathVar := maxsat.Var(fmt.Sprintf("path_%d", pathIdx))
							pathIdx++
							pathVars = append(pathVars, pathVar)
							// Forward: p → ei becomes ¬p ∨ ei
							for _, e := range pathEdges {
								constraints = append(constraints,
									maxsat.HardClause(pathVar.Negation(), reach(e.from, e.to)))
							}
							// Backward: (e1 ∧ ... ∧ en) → p becomes ¬e1 ∨ ... ∨ ¬en ∨ p
							clause := make([]maxsat.Lit, 0, len(pathEdges)+1)
							for _, e := range pathEdges {
								clause = append(clause, reach(e.from, e.to).Negation())
							}
							clause = append(clause, pathVar)
							constraints = append(constraints, maxsat.HardClause(clause...))
						}
					}
					if len(pathVars) > 0 {
						constraints = append(constraints, maxsat.HardClause(pathVars...))
					}
				}
			}
		}
	}

	// === SOFT CLAUSES ===

	// Maximize must-not-flow edges (minimize unknown edges)
	// Each soft clause ¬reach(a,b) with weight=1
	for _, e := range unknown {
		constraints = append(constraints, maxsat.SoftClause(reach(e.from, e.to).Negation()))
	}

	prob := maxsat.New(constraints...)
	model, _ := prob.Solve()
	if model == nil {
		panic("model is unsatisfiable")
	}

	// Print must-not-flow edges
	fmt.Println("Must-not-flow dataflow edges:")
	for _, e := range unknown {
		reachVar := fmt.Sprintf("r_%s->%s", e.from.String(), e.to.String())
		if val, ok := model[reachVar]; ok && !val {
			fmt.Printf("  %s -/-> %s\n", e.from.String(), e.to.String())
		}
	}

	return append(known, unknown...)
}

// reach creates a boolean variable representing the dataflow edge from→to
func reach(from, to dataflow.GraphNode) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("r_%s->%s", from.String(), to.String()))
}

func collectFunctionNodes(g *dataflow.SummaryGraph) []dataflow.GraphNode {
	var nodes []dataflow.GraphNode
	for _, param := range g.Params {
		nodes = append(nodes, param)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			nodes = append(nodes, ret)
		}
	}
	return nodes
}

func findNodeByName(nodes []dataflow.GraphNode, name string) dataflow.GraphNode {
	// Try to parse as ArgumentSNode or ReturnSNode
	snode, err := summaries.ParseSummaryNode(name)
	if err != nil {
		return nil
	}

	for _, n := range nodes {
		switch s := snode.(type) {
		case summaries.ArgumentSNode:
			if param, ok := n.(*dataflow.ParamNode); ok {
				if (s.Name != "" && param.SsaNode().Name() == s.Name) || param.Index() == s.Index {
					return n
				}
			}
		case summaries.ReturnSNode:
			if ret, ok := n.(*dataflow.ReturnValNode); ok {
				if ret.Index() == s.Index {
					return n
				}
			}
		}
	}
	return nil
}

func hasFlow(flows map[summaries.SummaryNode][]summaries.SummaryNode, from, to dataflow.GraphNode) bool {
	for f, tos := range flows {
		// Match from node
		fromSNode, err := summaries.ParseSummaryNode(f.String())
		if err != nil {
			continue
		}
		if !matchesNode(fromSNode, from) {
			continue
		}
		// Check if to node is in the list
		for _, t := range tos {
			toSNode, err := summaries.ParseSummaryNode(t.String())
			if err != nil {
				continue
			}
			if matchesNode(toSNode, to) {
				return true
			}
		}
	}
	return false
}

func matchesNode(snode summaries.SummaryNode, gnode dataflow.GraphNode) bool {
	switch s := snode.(type) {
	case summaries.ArgumentSNode:
		if param, ok := gnode.(*dataflow.ParamNode); ok {
			return (s.Name != "" && param.SsaNode().Name() == s.Name) || param.Index() == s.Index
		}
	case summaries.ReturnSNode:
		if ret, ok := gnode.(*dataflow.ReturnValNode); ok {
			return ret.Index() == s.Index
		}
	}
	return false
}

func findPathsThroughUnknown(src, dst dataflow.GraphNode, known, unknown []edge) [][]edge {
	knownGraph := make(map[string][]dataflow.GraphNode)
	unknownGraph := make(map[string][]edge)
	for _, e := range known {
		knownGraph[e.from.String()] = append(knownGraph[e.from.String()], e.to)
	}
	for _, e := range unknown {
		unknownGraph[e.from.String()] = append(unknownGraph[e.from.String()], e)
	}

	type state struct {
		node        dataflow.GraphNode
		unknownUsed []edge
		visited     map[string]bool
	}

	var paths [][]edge
	queue := []state{{node: src, unknownUsed: nil, visited: make(map[string]bool)}}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.node.String() == dst.String() {
			paths = append(paths, curr.unknownUsed)
			continue
		}

		if curr.visited[curr.node.String()] {
			continue
		}
		visited := make(map[string]bool)
		for k, v := range curr.visited {
			visited[k] = v
		}
		visited[curr.node.String()] = true

		for _, next := range knownGraph[curr.node.String()] {
			queue = append(queue, state{node: next, unknownUsed: curr.unknownUsed, visited: visited})
		}

		for _, e := range unknownGraph[curr.node.String()] {
			newUnknown := make([]edge, len(curr.unknownUsed))
			copy(newUnknown, curr.unknownUsed)
			newUnknown = append(newUnknown, e)
			queue = append(queue, state{node: e.to, unknownUsed: newUnknown, visited: visited})
		}
	}

	return paths
}

type edge struct {
	from  dataflow.GraphNode
	to    dataflow.GraphNode
	known bool
}

func (e edge) String() string {
	return fmt.Sprintf("%s->%s, known: %v", e.from, e.to, e.known)
}

func (e edge) key() string {
	return fmt.Sprintf("%s->%s", e.from.String(), e.to.String())
}

func intraEdgesNonSummary(g *dataflow.SummaryGraph) []edge {
	if !g.Constructed {
		panic(fmt.Errorf("summary graph for function %s must be constructed", g.Parent))
	}

	var res []edge
	seen := make(map[dataflow.GraphNode]struct{})
	var stack []dataflow.GraphNode

	// Start from params
	for _, param := range g.Params {
		stack = append(stack, param)
	}

	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}

		// Use both Out() and ForwardEdges
		for next := range n.Out() {
			stack = append(stack, next)
			// Exclude direct param-to-param and param-to-return edges (these are summary edges)
			_, fromIsParam := n.(*dataflow.ParamNode)
			_, toIsParam := next.(*dataflow.ParamNode)
			_, toIsReturn := next.(*dataflow.ReturnValNode)
			if fromIsParam && (toIsParam || toIsReturn) {
				continue
			}
			res = append(res, edge{from: n, to: next, known: true})
		}
	}

	return res
}

func interEdges(s *dataflow.State, g *dataflow.SummaryGraph) []edge {
	var res []edge
	for _, calleeToCall := range g.Callees {
		for f, call := range calleeToCall {
			calleeSummary, ok := s.FlowGraph.Summaries[f]
			if !ok {
				panic(fmt.Errorf("failed to find summary for function %s", f))
			}
			// callee return -> call node
			for _, rets := range calleeSummary.Returns {
				for _, ret := range rets {
					res = append(res, edge{from: ret, to: call, known: true})
				}
			}

			// call arg -> callee param
			for _, arg := range call.Args() {
				for _, param := range calleeSummary.Params {
					if param.Index() == arg.Index() {
						res = append(res, edge{from: arg, to: param, known: true})
						break
					}
				}
			}
		}
	}

	return res
}

func unknownEdges(s *dataflow.State, g *dataflow.SummaryGraph) []edge {
	// Return all possible edges between params and returns (permutations)
	// Exclude edges from return nodes (returns are outputs, no outgoing edges)
	var nodes []dataflow.GraphNode
	for _, param := range g.Params {
		nodes = append(nodes, param)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			nodes = append(nodes, ret)
		}
	}

	var res []edge
	for _, from := range nodes {
		// Skip return nodes as sources
		if _, isReturn := from.(*dataflow.ReturnValNode); isReturn {
			continue
		}
		for _, to := range nodes {
			if from != to {
				res = append(res, edge{from: from, to: to, known: false})
			}
		}
	}
	return res
}

func transitiveCallees(cg *callgraph.Graph, f *ssa.Function) []*ssa.Function {
	node, ok := cg.Nodes[f]
	if !ok {
		panic(fmt.Errorf("no callgraph node for function %s", f))
	}

	res := make(map[*ssa.Function]struct{})
	seen := make(map[*callgraph.Node]struct{})
	stack := []*callgraph.Node{node}

	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[n]; ok {
			continue
		}

		seen[n] = struct{}{}
		res[n.Func] = struct{}{}
		for _, edge := range node.Out {
			stack = append(stack, edge.Callee)
		}
	}

	return maps.Keys(res)
}

// permutations returns sucessive r length permutations of elements from
// iterable.
//
// Elements are treated as unique based on their position,
// not on their value. So if the input elements are unique, there
// will be no repeat values in each permutation.
//
//	permutations([]int{1, 2, 3}, 3) -> [[1 2 3] [1 3 2] [2 1 3] [2 3 1] [3 1 2] [3 2 1]]
//
// from https://github.com/Skarlso/goitertools/blob/99fdc18feb0ed914387a5da682a1d889e60b3869/itertools/itertools.go#L340
// TODO maybe take as a dependency or include license or write my own
func permutations[T any](iterable []T, r int) [][]T {
	pool := iterable
	n := len(pool)

	if r > n || r == 0 {
		return nil
	}

	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	cycles := make([]int, r)
	for i := range cycles {
		cycles[i] = n - i
	}

	result := make([]T, r)
	for i, el := range indices[:r] {
		result[i] = pool[el]
	}

	results := [][]T{result}

	for n > 0 {
		i := r - 1
		for ; i >= 0; i -= 1 {
			cycles[i] -= 1
			if cycles[i] == 0 {
				index := indices[i]
				for j := i; j < n-1; j += 1 {
					indices[j] = indices[j+1]
				}
				indices[n-1] = index
				cycles[i] = n - i
			} else {
				j := cycles[i]
				indices[i], indices[n-j] = indices[n-j], indices[i]

				result := make([]T, r)
				for k := 0; k < r; k += 1 {
					result[k] = pool[indices[k]]
				}

				results = append(results, result)

				break
			}
		}

		if i < 0 {
			return results
		}

	}

	return nil
}
