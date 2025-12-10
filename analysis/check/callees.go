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
	"fmt"
	"slices"

	"github.com/crillab/gophersat/maxsat"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// inferCalleeSummaries returns all the maximally-general (most data flow edges) callee summaries
// which satisfy wantSummary's must-not-flow requirements.
func inferCalleeSummaries(
	ctx context.Context, s *dataflow.State, g *dataflow.SummaryGraph, wantSummary summaries.DetailedSummary,
	via Method,
) (map[*dataflow.SummaryGraph][]summaries.DetailedSummary, error) {
	// "Leaf" function (no callees)
	if len(g.Callees) == 0 {
		return nil, nil
	}

	validMethods := []Method{General, Types}
	if !slices.Contains(validMethods, via) {
		panic(fmt.Errorf("invalid inference method: want one of %v, got %v", validMethods, via))
	}

	// First run the intra-procedural analysis
	dataflow.RunIntraProcedural(ctx, s, g)

	// Collect known (intra + inter) and unknown edges
	intraParent := intraEdges(g, nil)
	inter := interEdges(s, g)

	known := append(intraParent, inter...)
	unknown := make(map[*dataflow.CallNode][]edge)
	calleeGraphs := addCalleeEdges(s, g, via, &known, unknown)

	// Build MaxSAT problem
	var constraints []maxsat.Constr

	// Callees of the same function must have identical inferred summaries
	summaryConstrs := buildCalleeSummaryConstrs(unknown)
	constraints = append(constraints, summaryConstrs...)

	// Hard constraints for known edges
	var knownConstrs []maxsat.Constr
	for _, e := range known {
		constr := maxsat.HardClause(mayFlow(e))
		knownConstrs = append(knownConstrs, constr)
	}
	constraints = append(constraints, knownConstrs...)

	// Maximize may-flow edges (minimize must-not-flow)
	var maxConstrs []maxsat.Constr
	for _, edges := range unknown {
		for _, e := range edges {
			constr := maxsat.SoftClause(mayFlow(e))
			maxConstrs = append(maxConstrs, constr)
		}
	}
	constraints = append(constraints, maxConstrs...)

	// Transitivity
	transitiveConstrs := buildTransitivityConstrs(g, calleeGraphs)
	constraints = append(constraints, transitiveConstrs...)

	// Block must-not-flows in wantSummary (most-general summary - want edges)
	fGeneralEdges := mostGeneralEdges(g, nil, via)
	fWantEdges := summaryToEdges(wantSummary, g)
	for _, e := range fGeneralEdges {
		if !slices.Contains(fWantEdges, e) {
			constr := maxsat.HardClause(mayFlow(e).Negation())
			constraints = append(constraints, constr)
		}
	}

	// Find the optimal cost first
	prob := maxsat.New(constraints...)
	model, optimalCost := prob.Solve()
	if model == nil {
		return nil, fmt.Errorf("model is unsatisfiable")
	}

	// Enumerate all optimal models and convert them to summaries
	allOptimalModels := findAllOptimalModels(model, optimalCost, constraints, unknown)
	res := modelsToSummaries(s, allOptimalModels, unknown)

	return res, nil
}

// addCalleeEdges adds edges of all callees to known and unknown.
// It returns a map from each call node to the callee's summary graph.
//
// If the callee has intra-procedural information, then its dataflow edges are added to known.
// If not, its most-general summary edges are added to unknown.
// The most-general summary is computed by the method specified by parameter via.
func addCalleeEdges(
	s *dataflow.State, g *dataflow.SummaryGraph, via Method,
	known *[]edge, unknown map[*dataflow.CallNode][]edge,
) map[*dataflow.CallNode]*dataflow.SummaryGraph {
	calleeGraphs := make(map[*dataflow.CallNode]*dataflow.SummaryGraph)
	for _, calleeToCall := range g.Callees {
		for callee, call := range calleeToCall {
			calleeG, ok := s.FlowGraph.Summaries[callee]
			if !ok {
				panic(fmt.Errorf("no summary for callee %s", callee))
			}
			calleeGraphs[call] = calleeG
		}
	}

	for call, calleeG := range calleeGraphs {
		if calleeG.Constructed {
			edges := intraEdges(calleeG, call)
			*known = append(*known, edges...)
		} else {
			edges := mostGeneralEdges(calleeG, call, via)
			unknown[call] = edges
		}
	}

	return calleeGraphs
}

// buildCalleeSummaryConstrs returns the constraints to ensure that unknown edges for different callsites with the same callee are the same.
func buildCalleeSummaryConstrs(unknown map[*dataflow.CallNode][]edge) []maxsat.Constr {
	var summaryConstrs []maxsat.Constr
	for call := range unknown {
		edges := unknown[call]
		for otherCall := range unknown {
			if call == otherCall {
				continue
			}
			if call.Callee() != otherCall.Callee() {
				continue
			}

			otherEdges := unknown[otherCall]

			// Match edges semantically, not by position
			// Create a map from edge signature to edge for matching
			edgeMap := make(map[string]edge)
			for _, e := range edges {
				sig := edgeSignature(e)
				edgeMap[sig] = e
			}

			for _, otherE := range otherEdges {
				sig := edgeSignature(otherE)
				if e, ok := edgeMap[sig]; ok {
					// These edges correspond semantically
					// Constraint ensures e <-> otherE (in CNF)
					constrs := []maxsat.Constr{
						maxsat.HardClause(
							mayFlow(e).Negation(),
							mayFlow(otherE),
						),
						maxsat.HardClause(
							mayFlow(otherE).Negation(),
							mayFlow(e),
						),
					}
					summaryConstrs = append(summaryConstrs, constrs...)
				}
			}
		}
	}

	return summaryConstrs
}

func buildTransitivityConstrs(
	g *dataflow.SummaryGraph, calleeGraphs map[*dataflow.CallNode]*dataflow.SummaryGraph,
) []maxsat.Constr {
	var transitiveConstrs []maxsat.Constr
	allNodes := make(map[node]struct{})
	g.ForAllNodes(func(n dataflow.GraphNode) {
		allNodes[node{n, nil}] = struct{}{}
	})
	for call, cg := range calleeGraphs {
		cg.ForAllNodes(func(n dataflow.GraphNode) {
			allNodes[node{n, call}] = struct{}{}
		})
	}
	for a := range allNodes {
		for b := range allNodes {
			for c := range allNodes {
				if a != b && b != c && a != c {
					constr := maxsat.HardClause(
						mayFlow(edge{from: a, to: b}).Negation(),
						mayFlow(edge{from: b, to: c}).Negation(),
						mayFlow(edge{from: a, to: c}),
					)
					transitiveConstrs = append(transitiveConstrs, constr)
				}
			}
		}
	}

	return transitiveConstrs
}

func findAllOptimalModels(
	model maxsat.Model, optimalCost int, constraints []maxsat.Constr,
	unknown map[*dataflow.CallNode][]edge,
) []maxsat.Model {
	// Get all unknown edge variable names for blocking
	unknownVars := make(map[string]bool)
	for _, edges := range unknown {
		for _, e := range edges {
			unknownVars[mayFlow(e).Var] = true
		}
	}

	// Collect all models with the optimal cost
	allOptimalModels := []maxsat.Model{model}
	// Enumerate all other optimal solutions by blocking previous ones
	// Limit to prevent infinite loops
	maxSolutions := 100
	for len(allOptimalModels) < maxSolutions {
		// Create blocking clause: at least one UNKNOWN variable must differ from current model
		var blockingLits []maxsat.Lit
		for varName, val := range model {
			// Only block unknown edge variables, not all variables
			if !unknownVars[varName] {
				continue
			}
			lit := maxsat.Var(varName)
			if !val {
				lit = lit.Negation()
			}
			blockingLits = append(blockingLits, lit.Negation())
		}

		if len(blockingLits) == 0 {
			break // No unknown variables to block
		}

		// Add blocking clause as a hard constraint
		blockingConstr := maxsat.HardClause(blockingLits...)
		constraints = append(constraints, blockingConstr)

		// Create new problem with blocking clause
		prob := maxsat.New(constraints...)
		newModel, newCost := prob.Solve()

		// Stop if no more models or cost is worse
		if newModel == nil || newCost != optimalCost {
			break
		}

		allOptimalModels = append(allOptimalModels, newModel)
		model = newModel
	}

	return allOptimalModels
}

func modelsToSummaries(
	s *dataflow.State, allOptimalModels []maxsat.Model, unknown map[*dataflow.CallNode][]edge,
) map[*dataflow.SummaryGraph][]summaries.DetailedSummary {
	res := make(map[*dataflow.SummaryGraph][]summaries.DetailedSummary)
	for _, optimalModel := range allOptimalModels {
		// Extract may-flow edges from this model
		var allMayFlows []edge
		for _, edges := range unknown {
			for _, e := range edges {
				mayFlowVar := mayFlow(e).Var
				if val, ok := optimalModel[mayFlowVar]; ok && val {
					allMayFlows = append(allMayFlows, e)
				}
			}
		}

		// Convert edges to summaries
		calleeToSumm := unknownEdgesToSummaries(allMayFlows)

		// Add empty summaries for callees with no inferred edges
		for call := range unknown {
			callee := call.Callee()
			if _, ok := calleeToSumm[callee]; !ok {
				// Create empty summary
				emptySumm := summaries.DetailedSummary{
					Flows: make(map[summaries.SummaryNode][]summaries.SummaryNode),
				}
				calleeToSumm[callee] = emptySumm
			}
		}

		for callee, summ := range calleeToSumm {
			cg := s.FlowGraph.Summaries[callee]
			res[cg] = append(res[cg], summ)
		}
	}

	return res
}

// mayFlow creates a boolean variable representing the dataflow edge from→to
func mayFlow(e edge) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("%s->%s", e.from.String(), e.to.String()))
}

// mostGeneralEdges returns the edges corresponding to the most-general summary of g.
// The parameter via is used to optionally filter out some edges.
//
// TODO merge this logic with newMostGeneralDetailedSummary
func mostGeneralEdges(g *dataflow.SummaryGraph, call *dataflow.CallNode, via Method) []edge {
	flows := mostGeneralFlows(g)
	if via == Types {
		flows = checkSummaryTypes(flows).badFlows
	}
	var edges []edge
	for _, fl := range flows {
		edges = append(edges, edge{from: node{fl.from, call}, to: node{fl.to, call}})
	}

	return edges
}

// summaryNodes returns all parameter and return nodes from a summary graph
func summaryNodes(g *dataflow.SummaryGraph) []dataflow.GraphNode {
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

// node represents a dataflow graph node, optionally scoped to a specific call site.
//
// The call site is important because if a function is called twice, then there needs to be two
// different nodes for each node in the callee: one for each call site.
type node struct {
	n    dataflow.GraphNode
	call *dataflow.CallNode
}

func (n node) String() string {
	if n.call == nil {
		return dataflow.GraphNodeDesc(n.n)
	}
	return fmt.Sprintf("%s_%s", dataflow.GraphNodeDesc(n.call), dataflow.GraphNodeDesc(n.n))
}

// edge represents a dataflow edge between two nodes
type edge struct {
	from node
	to   node
}

func (e edge) String() string {
	return fmt.Sprintf("%s->%s", e.from.String(), e.to.String())
}

// intraEdges collects all edges within a summary graph, scoped to a specific call site
func intraEdges(g *dataflow.SummaryGraph, call *dataflow.CallNode) []edge {
	var res []edge
	// Collect all edges in the graph, not just those reachable from params
	g.ForAllNodes(func(n dataflow.GraphNode) {
		for next := range n.Out() {
			res = append(res, edge{from: node{n: n, call: call}, to: node{n: next, call: call}})
		}
	})
	return res
}

// interEdges collects edges between caller and callee (argument passing and return values)
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
					res = append(res, edge{from: node{ret, call}, to: node{call, nil}})
				}
			}

			// call arg -> callee param
			for _, arg := range call.Args() {
				for _, param := range calleeSummary.Params {
					if param.Index() == arg.Index() {
						res = append(res, edge{from: node{arg, nil}, to: node{param, call}})
						break
					}
				}
			}

			// pointer-like callee param -> call arg
			for _, param := range calleeSummary.Params {
				if pointer.CanPoint(param.Type()) {
					for _, arg := range call.Args() {
						if param.Index() == arg.Index() {
							res = append(res, edge{from: node{param, call}, to: node{arg, nil}})
						}
					}
				}
			}
		}
	}

	return res
}

// summaryToEdges converts a frontend summary to internal edge representation
func summaryToEdges(s summaries.DetailedSummary, g *dataflow.SummaryGraph) []edge {
	var res []edge
	for from, tos := range s.Flows {
		fromNode := findNode(g, from)
		if fromNode == nil {
			panic(fmt.Errorf("failed to find graphnode for %v", from))
		}
		for _, to := range tos {
			toNode := findNode(g, to)
			if toNode == nil {
				panic(fmt.Errorf("failed to find graphnode for %v", to))
			}
			res = append(res, edge{from: node{fromNode, nil}, to: node{toNode, nil}})
		}
	}

	return res
}

// unknownEdgesToSummaries converts inferred edges to frontend dataflow summaries
func unknownEdgesToSummaries(unknown []edge) map[*ssa.Function]summaries.DetailedSummary {
	calleeFlows := make(map[*ssa.Function]summaries.DetailedSummary)
	for _, e := range unknown {
		if e.from.call != e.to.call {
			panic(fmt.Errorf("invalid unknown edge: %+v", e))
		}

		callee := e.from.call.Callee()
		flows, ok := calleeFlows[callee]
		if !ok {
			flows = summaries.DetailedSummary{
				Flows: make(map[summaries.SummaryNode][]summaries.SummaryNode),
			}
		}
		from := newSummaryNode(e.from.n)
		to := newSummaryNode(e.to.n)
		if slices.Contains(flows.Flows[from], to) {
			continue
		}
		flows.Flows[from] = append(flows.Flows[from], to)
		calleeFlows[callee] = flows
	}

	return calleeFlows
}

func findNode(g *dataflow.SummaryGraph, sn summaries.SummaryNode) dataflow.GraphNode {
	var res dataflow.GraphNode
	g.ForAllNodes(func(n dataflow.GraphNode) {
		// TODO use new iteration protocol to implement ForAllNodes to break when found
		if matchesNode(sn, n) {
			res = n
		}
	})

	return res
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

// edgeSignature creates a semantic signature for an edge based on node types and indices.
// This allows matching edges across different call sites.
func edgeSignature(e edge) string {
	return fmt.Sprintf("%s->%s", nodeSignature(e.from.n), nodeSignature(e.to.n))
}

// nodeSignature creates a semantic signature for a node that is not specific to its enclosing
// (parent) function.
func nodeSignature(n dataflow.GraphNode) string {
	switch node := n.(type) {
	case *dataflow.ParamNode:
		return fmt.Sprintf("param:%d:%s", node.Index(), node.SsaNode().Name())
	case *dataflow.ReturnValNode:
		return fmt.Sprintf("ret:%d", node.Index())
	default:
		return dataflow.GraphNodeDesc(n)
	}
}

// For debugging:

// func dbgConstrs(topic string, constrs []maxsat.Constr) {
// 	fmt.Println(topic)
// 	for _, c := range constrs {
// 		fmt.Printf("\t%v\n", c)
// 	}
// }

// func dbgEdges(topic string, edges []edge) {
// 	fmt.Println(topic)
// 	for _, e := range edges {
// 		fmt.Printf("\t%+v\n", e)
// 	}
// }
