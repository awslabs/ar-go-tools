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
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// inferCalleeSummaries returns all the maximally-general (most data flow edges) callee summaries
// which satisfy the summary's must-not-flow requirements mustNotFlows.
// It also adds any potential sources of unsoundness to unsoundness.
func inferCalleeSummaries(
	ctx context.Context, s *dataflow.State, g *dataflow.SummaryGraph, mustNotFlows []flow,
	unsoundness *Unsoundness, via Method,
) (map[*ssa.Function][]summaries.DetailedSummary, error) {
	if len(g.Callees) == 0 {
		s.Logger.Tracef("function %s is a leaf function (no callees)\n", g.Parent)
		return nil, nil
	}

	validMethods := []Method{General, Types}
	if !slices.Contains(validMethods, via) {
		panic(fmt.Errorf("invalid inference method: want one of %v, got %v", validMethods, via))
	}

	// First run the intra-procedural analysis
	if summ, ok := s.FlowGraph.Summaries[g.Parent]; ok && summ.Constructed {
		s.Logger.Tracef(
			"using already-computed intra-procedural results for function %s\n", g.Parent)
		g = summ
	} else {
		s.Logger.Tracef("running intra-procedural analysis on function %s...\n", g.Parent)
		if _, err := dataflow.RunIntraProcedural(ctx, s, g); err != nil {
			return nil, fmt.Errorf("failed to run intra-procedural analysis: %v", err)
		}
		if g.Unsoundness().HasAny() {
			unsoundness.DataflowFeatures = newUnsoundDataflowFeatures(g.Unsoundness())
			return nil, nil
		}
	}

	// Collect known (intra + inter) and unknown may-flow edges
	intraParent := intraMayFlowEdges(g, nil)
	inter := interMayFlowEdges(s, g)

	knownMayFlow := append(intraParent, inter...)
	unknownMayFlow := make(map[*dataflow.CallNode][]edge)
	calleeGraphs := addCalleeMayFlowEdges(s, g, via, &knownMayFlow, unknownMayFlow)

	if s.Logger.LogsTrace() {
		dbgEdges(s, "intra parent edges of "+g.Parent.Name()+":", intraParent)
		dbgEdges(s, "inter edges of "+g.Parent.Name()+".", inter)
		dbgEdges(s, "known edges with callees of "+g.Parent.Name()+":", knownMayFlow)
		for call, edges := range unknownMayFlow {
			dbgEdges(s, "unknown edges for call to "+call.FuncString()+":", edges)
		}
	}

	// Build MaxSAT problem
	var constraints []maxsat.Constr

	// Callees of the same function must have identical inferred summaries
	summaryConstrs := buildCalleeSummaryConstrs(unknownMayFlow)
	constraints = append(constraints, summaryConstrs...)

	// Hard constraints for known may-flow edges
	var knownConstrs []maxsat.Constr
	for _, e := range knownMayFlow {
		constr := maxsat.HardClause(mayFlow(e))
		knownConstrs = append(knownConstrs, constr)
	}
	constraints = append(constraints, knownConstrs...)

	// Maximize unknown may-flow edges (minimize must-not-flow)
	var maxConstrs []maxsat.Constr
	for _, edges := range unknownMayFlow {
		for _, e := range edges {
			constr := maxsat.SoftClause(mayFlow(e))
			maxConstrs = append(maxConstrs, constr)
		}
	}
	constraints = append(constraints, maxConstrs...)

	// Transitivity
	transitiveConstrs := buildTransitivityConstrs(g, calleeGraphs)
	constraints = append(constraints, transitiveConstrs...)

	// Block must-not-flows
	mustNotFlowEdges := funcutil.Map(mustNotFlows, func(fl flow) edge { return newEdge(fl, nil) })
	for _, e := range mustNotFlowEdges {
		constr := maxsat.HardClause(mayFlow(e).Negation())
		constraints = append(constraints, constr)
	}

	// Find the optimal cost first
	prob := maxsat.New(constraints...)
	model, optimalCost := prob.Solve()
	if model == nil {
		// An unsatisfiable model is not necessarily an error. For example, if mustNotFlows
		// contradicts a satisfiable may-flow edge generated from a successfull intra-procedural
		// analysis, then the model will be unsatisfiable.
		s.Logger.Debugf(
			"callee summary inference MAXSAT model for function %s is unsatisfiable\n", g.Parent)
		return nil, nil
	}

	// Enumerate all optimal models and convert them to summaries
	allOptimalModels := findAllOptimalModels(model, optimalCost, constraints, unknownMayFlow)
	res := modelsToSummaries(s, allOptimalModels, unknownMayFlow)

	return res, nil
}

// addCalleeMayFlowEdges adds edges of all callees to known and unknown.
// It returns a map from each call node to the callee's summary graph in terms of its may-flow
// edges.
//
// If the callee has intra-procedural information, then its dataflow edges are added to known.
// If not, its most-general summary edges are added to unknown.
// The most-general summary is computed by the method specified by parameter via.
func addCalleeMayFlowEdges(
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
			edges := intraMayFlowEdges(calleeG, call)
			*known = append(*known, edges...)
		} else {
			edges := mostGeneralEdges(calleeG, call, via)
			unknown[call] = edges
		}
	}

	return calleeGraphs
}

// buildCalleeSummaryConstrs returns the constraints to ensure that unknown edges for different
// callsites with the same callee are the same.
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
		if skipNode(n) {
			return
		}
		allNodes[node{n, nil}] = struct{}{}
	})
	for call, cg := range calleeGraphs {
		cg.ForAllNodes(func(n dataflow.GraphNode) {
			if skipNode(n) {
				return
			}
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
) map[*ssa.Function][]summaries.DetailedSummary {
	res := make(map[*ssa.Function][]summaries.DetailedSummary)
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
		calleeToSumm := mayFlowEdgesToSummaries(allMayFlows)

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
			cg, ok := s.FlowGraph.Summaries[callee]
			if !ok {
				panic(fmt.Errorf("no summary found for callee: %s", callee))
			}

			// Check if this summary already exists to avoid duplicates.
			// There may be duplicate summaries even for unique MaxSAT models because there may be
			// different variable (may-flow) assignments which map to the same summary.
			existing := res[cg.Parent]
			isDuplicate := false
			for _, existingSumm := range existing {
				if summariesEqual(summ, existingSumm) {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				continue
			}

			res[cg.Parent] = append(res[cg.Parent], summ)
		}
	}

	return res
}

// mayFlow creates a boolean variable representing the dataflow edge from→to
func mayFlow(e edge) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("%s->%s", e.from.String(), e.to.String()))
}

// mostGeneralEdges returns the edges corresponding to the most-general summary of g (as may-flows).
// The parameter via is used to optionally filter out some edges (only Types is supported for now).
func mostGeneralEdges(g *dataflow.SummaryGraph, call *dataflow.CallNode, via Method) []edge {
	if !(via == General || via == Types) {
		panic(fmt.Errorf("unsupported most-general method: %v", via))
	}

	flows := mostGeneralFlows(g)
	// TODO Maybe add more analyses?
	// We're trying to balance maximizing may-flow edges AND the probability that we will be able
	// to prove that these may-flow edges hold.
	if via == Types {
		flows = filterFlowsTypes(flows)
	}
	var edges []edge
	for _, fl := range flows {
		edges = append(edges, newEdge(fl, call))
	}

	return edges
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
		return graphNodeDesc(n.n)
	}
	return fmt.Sprintf("%s_%s", graphNodeDesc(n.call), graphNodeDesc(n.n))
}

func graphNodeDesc(g dataflow.GraphNode) string {
	switch x := g.(type) {
	case *dataflow.ParamNode:
		return fmt.Sprintf("param:%s", x.SsaNode().Name())
	case *dataflow.CallNode:
		return fmt.Sprintf("call:%s", x.CallSite().String())
	case *dataflow.BuiltinCallNode:
		return fmt.Sprintf("builtin-call:%s", x.CallSite().String())
	case *dataflow.CallNodeArg:
		return fmt.Sprintf("arg#%v:%s", x.Index(), x.ParentNode().CallSite().String())
	case *dataflow.ReturnValNode:
		return fmt.Sprintf("ret#%d", x.Index())
	case *dataflow.BoundVarNode:
		return fmt.Sprintf("bound-var:%s", x.Value().Name())
	case *dataflow.FreeVarNode:
		return fmt.Sprintf("free-var:%s", x.SsaNode().Name())
	case *dataflow.AccessGlobalNode:
		return fmt.Sprintf("global:%v", x.Global.Value())
	default:
		panic(fmt.Errorf("unsupported node type: %v %T", g, g))
	}
}

// edge represents a dataflow edge between two nodes
type edge struct {
	from node
	to   node
}

func newEdge(fl flow, call *dataflow.CallNode) edge {
	return edge{
		from: node{fl.from, call},
		to:   node{fl.to, call},
	}
}

func (e edge) String() string {
	return fmt.Sprintf("%s->%s", e.from.String(), e.to.String())
}

// intraMayFlowEdges returns all the may-flow edges within a summary graph, scoped to a specific
// call site.
func intraMayFlowEdges(g *dataflow.SummaryGraph, call *dataflow.CallNode) []edge {
	var res []edge
	// Collect all edges in the graph, not just those reachable from params
	g.ForAllNodes(func(n dataflow.GraphNode) {
		if skipNode(n) {
			return
		}

		for next := range n.Out() {
			if skipNode(next) {
				continue
			}
			e := edge{from: node{n: n, call: call}, to: node{n: next, call: call}}
			res = append(res, e)
		}
	})

	return res
}

// interMayFlowEdges returns the interprocedural may-flow edges between callers and their
// corresponding callees.
func interMayFlowEdges(s *dataflow.State, g *dataflow.SummaryGraph) []edge {
	var res []edge
	for _, calleeToCall := range g.Callees {
		for callee, call := range calleeToCall {
			calleeSummary, ok := s.FlowGraph.Summaries[callee]
			if !ok {
				calleeSummary = dataflow.NewSummaryGraph(
					s, callee, dataflow.GetUniqueFunctionID(), nil, nil)
				s.FlowGraph.Summaries[callee] = calleeSummary
			}
			// After building a summary graph, link the summaries together to form the implicit
			// inter-procedural data flow edges. This is important because otherwise, summaries are
			// incomplete. For example, a summary's referring make closure instructions will be
			// empty.
			s.FlowGraph.BuildGraph(false)

			// callee return -> call node
			for _, rets := range calleeSummary.Returns {
				for _, ret := range rets {
					e := edge{from: node{ret, call}, to: node{call, nil}}
					res = append(res, e)
				}
			}

			// call arg -> callee param
			for _, arg := range call.Args() {
				for _, param := range calleeSummary.Params {
					if param.Index() == arg.Index() {
						e := edge{from: node{arg, nil}, to: node{param, call}}
						res = append(res, e)
						break
					}
				}
			}

			// pointer-like callee param -> call arg
			for _, param := range calleeSummary.Params {
				if isPointerLike(param.Type()) {
					for _, arg := range call.Args() {
						if param.Index() == arg.Index() {
							e := edge{from: node{param, call}, to: node{arg, nil}}
							res = append(res, e)
						}
					}
				}
			}

			for _, closure := range calleeSummary.ReferringMakeClosures {
				// bound variable -> free variable
				// free variable -> bound variable
				for i, bv := range closure.BoundVars() {
					fv := calleeSummary.Parent.FreeVars[i]
					fvNode, ok := calleeSummary.FreeVars[fv]
					if !ok {
						panic(fmt.Errorf(
							"no free variable for bound variable %v in closure %v", bv, closure))
					}
					e := edge{from: node{bv, nil}, to: node{fvNode, call}}
					res = append(res, e)
					e = edge{from: node{fvNode, call}, to: node{bv, nil}}
					res = append(res, e)
				}
			}
		}
	}

	return res
}

func skipNode(n dataflow.GraphNode) bool {
	switch n := n.(type) {
	case *dataflow.BoundLabelNode:
		closure := n.DestInfo().MakeClosure
		if n.Graph().Parent != closure.Parent() {
			// If a bound label is created in a different function as its corresponding make
			// closure instruction, it means that there is no corresponding free variable
			// inside the closure for this bound label value. We do not support summary
			// nodes for closure-specific inputs/outputs other than bound and free
			// variables. It does not make sense to summarize closures with bound labels
			// because the input/output bound label value is not local to the closure: it is
			// scoped to the completely different function that allocated the bound label.
			//
			// TODO add unsoundness instead of panicking
			panic(fmt.Errorf(
				"cannot check summary where bound label closure is non-local. "+
					"label: %v in %v, closure: %v in %v",
				n, n.ParentName(), closure, closure.Parent()))
		}
		// We can soundly skip adding edges for bound labels which are created in the same
		// function as their corresponding make closure instructions, as there will be a
		// bound variable that references the same value.
		return true
	case *dataflow.ClosureNode:
		// There's currently no need to track flows to closure nodes since we do not support
		// function-like summary nodes.
		return true
	case *dataflow.IfNode:
		// We do not support checking implicit data flows.
		return true
	default:
		return false
	}
}

// mayFlowEdgesToSummaries converts inferred edges to frontend dataflow summaries
func mayFlowEdgesToSummaries(unknown []edge) map[*ssa.Function]summaries.DetailedSummary {
	calleeFlows := make(map[*ssa.Function]summaries.DetailedSummary)
	for _, e := range unknown {
		if e.from.call != e.to.call {
			panic(fmt.Errorf("invalid unknown may-flow edge: %+v", e))
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
	if res == nil {
		panic(fmt.Errorf("failed to find graph node for summary node: %v", sn))
	}

	return res
}

func matchesNode(snode summaries.SummaryNode, gnode dataflow.GraphNode) bool {
	switch s := snode.(type) {
	case summaries.ReceiverSNode:
		if param, ok := gnode.(*dataflow.ParamNode); ok {
			if param.Graph().Parent.Signature.Recv() == nil {
				panic(fmt.Errorf("expected function for recv summary node to have a receiver"))
			}
			return param.Index() == 0
		}
	case summaries.ArgumentSNode:
		if param, ok := gnode.(*dataflow.ParamNode); ok {
			if param.Graph().Parent.Signature.Recv() != nil {
				return (s.Name != "" && param.SsaNode().Name() == s.Name) ||
					param.Index() == s.Index+1
			}
			return (s.Name != "" && param.SsaNode().Name() == s.Name) ||
				param.Index() == s.Index
		}
	case summaries.ReturnSNode:
		if ret, ok := gnode.(*dataflow.ReturnValNode); ok {
			return ret.Index() == s.Index
		}
	case summaries.FreeVarSNode:
		if fv, ok := gnode.(*dataflow.FreeVarNode); ok {
			return fv.SsaNode().Name() == s.Name
		}
	default:
		panic(fmt.Errorf("unhandled summary node type: %T", snode))
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
	case *dataflow.FreeVarNode:
		return fmt.Sprintf("fv:%s", node.SsaNode().Name())
	default:
		panic(fmt.Errorf("invalid summary node: %v", n))
	}
}

// summariesEqual checks if two DetailedSummary instances are identical.
func summariesEqual(a, b summaries.DetailedSummary) bool {
	if len(a.Flows) != len(b.Flows) {
		return false
	}

	for fromNode, aTargets := range a.Flows {
		bTargets, ok := b.Flows[fromNode]
		if !ok || len(aTargets) != len(bTargets) {
			return false
		}

		// Check if all targets match (order doesn't matter)
		for _, aTarget := range aTargets {
			if !slices.Contains(bTargets, aTarget) {
				return false
			}
		}
	}

	return true
}

// For debugging:

// func dbgConstrs(topic string, constrs []maxsat.Constr) {
// 	fmt.Println(topic)
// 	for _, c := range constrs {
// 		fmt.Printf("\t%v\n", c)
// 	}
// }

func dbgEdges(s *dataflow.State, topic string, edges []edge) {
	s.Logger.Tracef("%s\n", topic)
	if len(edges) == 0 {
		s.Logger.Tracef("\t<none>\n")
		return
	}
	for _, e := range edges {
		s.Logger.Tracef("\t%+v\n", e)
	}
}
