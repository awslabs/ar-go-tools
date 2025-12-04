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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// findSubspecs infers the most restrictive valid dataflow summary for callees
// using a pure MaxSAT encoding.
// It returns the must-not-flow edges needed to satisfy wantSummary.
//
// TODO return may-flow instead of must-not-flow
// Goal is to output a summary which we check recursively
func findSubspecs(s *dataflow.State, g *dataflow.SummaryGraph, wantSummary summaries.FrontendDataflowSummary) []edge {
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
			dataflow.MakeMostGeneralNoPtr(calleeG)
			edges := intraEdges(calleeG, call)
			unknown[call] = edges
			// Reset constructed to false because MakeMostGeneralNoPtr sets it to true
			calleeG.Constructed = false
		}
	}

	// Build MaxSAT problem
	var constraints []maxsat.Constr

	// Callees of the same function must have identical inferred summaries
	var summaryConstrs []maxsat.Constr
	for call := range unknown {
		for otherCall, edges := range unknown {
			if call == otherCall {
				continue
			}
			if call.Callee() == otherCall.Callee() {
				otherEdges := unknown[otherCall]
				for i, e := range edges {
					constrs := []maxsat.Constr{
						maxsat.HardClause(
							mayFlow(e).Negation(),
							mayFlow(otherEdges[i]),
						),
						maxsat.HardClause(
							mayFlow(otherEdges[i]).Negation(),
							mayFlow(e),
						),
					}
					summaryConstrs = append(summaryConstrs, constrs...)
				}
			}
		}
	}
	constraints = append(constraints, summaryConstrs...)
	// dbgConstrs("summary constrs:", summaryConstrs)

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
	fNodes := collectFunctionNodes(g)
	for _, from := range fNodes {
		// Skip edges starting from return nodes
		if _, isRet := from.(*dataflow.ReturnValNode); isRet {
			continue
		}
		for _, to := range fNodes {
			if from != to {
				fGeneralEdges = append(fGeneralEdges, edge{from: node{n: from, call: nil}, to: node{n: to, call: nil}})
			}
		}
	}
	fWantEdges := summaryEdges(wantSummary, g)
	for _, e := range fGeneralEdges {
		want := false
		for _, we := range fWantEdges {
			if we == e {
				want = true
				break
			}
		}
		if !want {
			constr := maxsat.HardClause(mayFlow(e).Negation())
			constraints = append(constraints, constr)
		}
	}

	prob := maxsat.New(constraints...)
	model, _ := prob.Solve()
	if model == nil {
		panic("model is unsatisfiable")
	}

	// Return must-not-flow (negation of may-flow) edges
	var res []edge
	for _, edges := range unknown {
		// TODO merge same calls
		for _, e := range edges {
			mayFlowVar := mayFlow(e).Var
			if val, ok := model[mayFlowVar]; ok && !val {
				res = append(res, e)
			}
		}
	}

	return res
}

// mayFlow creates a boolean variable representing the dataflow edge from→to
func mayFlow(e edge) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("%s->%s", e.from.String(), e.to.String()))
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

func summaryEdges(s summaries.FrontendDataflowSummary, g *dataflow.SummaryGraph) []edge {
	var res []edge
	for from, tos := range s.Summary().Flows {
		fromNode := findNode(g, from)
		if fromNode == nil {
			panic(fmt.Errorf("failed to find graphnode for %v", from))
		}
		for _, to := range tos {
			toNode := findNode(g, to)
			if fromNode == nil {
				panic(fmt.Errorf("failed to find graphnode for %v", to))
			}
			res = append(res, edge{from: node{fromNode, nil}, to: node{toNode, nil}})
		}
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

func dbgConstrs(topic string, constrs []maxsat.Constr) {
	fmt.Println(topic)
	for _, c := range constrs {
		fmt.Printf("\t%v\n", c)
	}
}
