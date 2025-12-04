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
	"slices"

	"github.com/crillab/gophersat/maxsat"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// inferCalleeSummaries infers the most general possibly-valid dataflow summary for callees
// using a pure MaxSAT encoding.
// It returns all the maximally-general (most flow edges) callee summaries which satisfy
// wantSummary's must-not-flow requirements.
func inferCalleeSummaries(
	s *dataflow.State, g *dataflow.SummaryGraph, wantSummary summaries.FrontendDataflowSummary,
	via Method,
) map[*dataflow.SummaryGraph][]summaries.FrontendDataflowSummary {
	validMethods := []Method{General, Types}
	if !slices.Contains(validMethods, via) {
		panic(fmt.Errorf("invalid inference method: want one of %v, got %v", validMethods, via))
	}

	// Collect known (intra + inter) and unknown edges
	intraParent := intraEdges(g, nil)
	inter := interEdges(s, g)

	known := append(intraParent, inter...)

	unknown := make(map[*dataflow.CallNode][]edge)
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
			known = append(known, edges...)
		} else {
			switch via {
			case General:
				dataflow.MakeMostGeneralNoPtr(calleeG)
			case Types:
				dataflow.MakeMostGeneral(calleeG)
			}
			edges := intraEdges(calleeG, call)
			unknown[call] = edges
			// Reset constructed to false because MakeMostGeneral sets it to true
			calleeG.Constructed = false
		}
	}

	// Build MaxSAT problem
	var constraints []maxsat.Constr

	// Callees of the same function must have identical inferred summaries
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
	constraints = append(constraints, transitiveConstrs...)

	// Block must-not-flows in wantSummary
	// Generate all possible edges between function-level nodes (params and returns only)
	var fGeneralEdges []edge
	fNodes := summaryNodes(g)
	for _, from := range fNodes {
		// Skip edges starting from return nodes
		if _, isRet := from.(*dataflow.ReturnValNode); isRet {
			continue
		}
		for _, to := range fNodes {
			if from != to {
				fGeneralEdges = append(fGeneralEdges,
					edge{from: node{n: from, call: nil}, to: node{n: to, call: nil}})
			}
		}
	}
	fWantEdges := summaryToEdges(wantSummary, g)
	for _, e := range fGeneralEdges {
		if !slices.Contains(fWantEdges, e) {
			constr := maxsat.HardClause(mayFlow(e).Negation())
			constraints = append(constraints, constr)
		}
	}

	prob := maxsat.New(constraints...)

	// Find the optimal cost first
	model, optimalCost := prob.Solve()
	if model == nil {
		panic("model is unsatisfiable")
	}

	// Collect all models with the optimal cost
	allOptimalModels := []maxsat.Model{model}

	// Get all unknown edge variable names for blocking
	unknownVars := make(map[string]bool)
	for _, edges := range unknown {
		for _, e := range edges {
			unknownVars[mayFlow(e).Var] = true
		}
	}

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
		prob = maxsat.New(constraints...)
		newModel, newCost := prob.Solve()

		// Stop if no more models or cost is worse
		if newModel == nil || newCost != optimalCost {
			break
		}

		allOptimalModels = append(allOptimalModels, newModel)
		model = newModel
	}

	// Convert all optimal models to summaries
	res := make(map[*dataflow.SummaryGraph][]summaries.FrontendDataflowSummary)

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

type edge struct {
	from node
	to   node
}

func (e edge) String() string {
	return fmt.Sprintf("%s->%s", e.from.String(), e.to.String())
}

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

func summaryToEdges(s summaries.FrontendDataflowSummary, g *dataflow.SummaryGraph) []edge {
	var res []edge
	for from, tos := range s.Summary().Flows {
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

func unknownEdgesToSummaries(unknown []edge) map[*ssa.Function]summaries.FrontendDataflowSummary {
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

	res := make(map[*ssa.Function]summaries.FrontendDataflowSummary)
	for callee, flows := range calleeFlows {
		sm := summaries.NewFrontendDataflowSummary(callee, flows)
		res[callee] = sm
	}

	return res
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

func dbgEdges(edges []edge) {
	for _, e := range edges {
		fmt.Printf("\t%+v\n", e)
	}
}

// edgeSignature creates a semantic signature for an edge based on node types and indices
// This allows matching edges across different call sites
func edgeSignature(e edge) string {
	return fmt.Sprintf("%s->%s", nodeSignature(e.from.n), nodeSignature(e.to.n))
}

// nodeSignature creates a semantic signature for a node
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

func dbgConstrs(topic string, constrs []maxsat.Constr) {
	fmt.Println(topic)
	for _, c := range constrs {
		fmt.Printf("\t%v\n", c)
	}
}
