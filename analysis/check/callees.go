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
	"strings"
	"time"

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
	ctx context.Context, s *dataflow.State, g *dataflow.SummaryGraph,
	nodePathLen map[dataflow.GraphNode]int, mustNotFlows []flow,
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
		s.Logger.Debugf("running intra-procedural analysis on function %s...\n", g.Parent)
		start := time.Now()
		if _, err := dataflow.RunIntraProcedural(ctx, s, g); err != nil {
			return nil, fmt.Errorf("failed to run intra-procedural analysis: %v", err)
		}
		intraUnsoundness := findUnsoundDataflowFeatures(g.Parent)
		if !intraUnsoundness.isSound() {
			s.Logger.Warnf("intra-procedural analysis for function %s is unsound", g.Parent)
			unsoundness.DataflowFeatures = intraUnsoundness
		}
		s.Logger.Debugf(
			"intra-procedural analysis on function %s took %s\n",
			g.Parent, time.Since(start))
	}

	start := time.Now()

	// Use mustNotFlows to determine precision for parent's intra-procedural edges
	knownIntra := knownIntraEdges(s, g, nil, unsoundness, nodePathLen)
	// Use parent's intra edges to determine precision for unknown inter-procedural edges
	unknownInter := unknownInterEdges(s, g, nodePathLen)
	// Use parent's intra edges to determine precision for unknown intra-procedural edges
	// (edges resulting from the inter-procedural edges).
	unknownIntra := unknownIntraEdges(s, g, unsoundness, nodePathLen, knownIntra)

	// hardEdges are the edges that make up the taint flow graph of g.Parent.
	hardEdges := slices.Concat(knownIntra, unknownInter, unknownIntra)

	// unknownMayFlow are the edges that make up the callee taint flow summaries.
	unknownMayFlow := make(map[*dataflow.CallNode][]edge)
	addCalleeMayFlowEdges(
		s, g, via, &hardEdges, unknownMayFlow, unsoundness, nodePathLen)

	if s.Logger.LogsTrace() {
		dbgEdges(s, "known intra parent edges of "+g.Parent.Name()+":", knownIntra)
		dbgEdges(s, "unknown inter edges of "+g.Parent.Name()+".", unknownInter)
		dbgEdges(s, "unknown intra edges of "+g.Parent.Name()+".", unknownIntra)
		for call, edges := range unknownMayFlow {
			dbgEdges(s, "unknown summary edges for call "+call.CallSite().String()+":", edges)
		}
	}
	allEdges := make(map[edge]struct{})
	for _, e := range hardEdges {
		allEdges[e] = struct{}{}
	}
	for _, edges := range unknownMayFlow {
		for _, e := range edges {
			allEdges[e] = struct{}{}
		}
	}
	s.Logger.Debugf("call to %s has %d total edges", g.Parent.String(), len(allEdges))

	// Build MaxSAT problem
	s.Logger.Debugf("computing problem constraints...")
	var constraints []maxsat.Constr
	// Callees of the same function must have identical inferred summaries
	summaryConstrs := buildCalleeSummaryConstrs(unknownMayFlow)
	constraints = append(constraints, summaryConstrs...)

	// Hard constraints for known may-flow edges
	s.Logger.Debugf("[%d constraints] computing hard contraints for known may-flow edges",
		len(constraints))
	var knownConstrs []maxsat.Constr
	for _, e := range hardEdges {
		constr := maxsat.HardClause(mayFlow(e))
		knownConstrs = append(knownConstrs, constr)
	}
	constraints = append(constraints, knownConstrs...)

	// Maximize unknown may-flow edges (minimize must-not-flow)
	s.Logger.Debugf("[%d constraints] computing soft constraints for callee's may-flow edges",
		len(constraints))
	var maxConstrs []maxsat.Constr
	for _, edges := range unknownMayFlow {
		for _, e := range edges {
			constr := maxsat.SoftClause(mayFlow(e))
			maxConstrs = append(maxConstrs, constr)
		}
	}
	constraints = append(constraints, maxConstrs...)

	// Transitivity
	transitiveConstrs := buildTransitivityConstrs(s, allEdges)
	s.Logger.Debugf("[%d constraints] added %d transitivity constraints",
		len(constraints), len(transitiveConstrs))
	constraints = append(constraints, transitiveConstrs...)

	// Block must-not-flows
	mustNotFlowEdges := funcutil.Map(mustNotFlows, func(fl flow) edge { return newEdge(fl, nil) })
	mnfCount := 0
	for _, e := range mustNotFlowEdges {
		fromPaths := leafPathsUpTo(e.from.n.Type(), nodePathLen[e.from.n])
		toPaths := leafPathsUpTo(e.to.n.Type(), nodePathLen[e.to.n])
		// Also include the base paths
		fromPaths = append(fromPaths, e.from.path)
		toPaths = append(toPaths, e.to.path)

		for _, fromPath := range fromPaths {
			for _, toPath := range toPaths {
				fn := node{e.from.n, e.from.call, fromPath}
				tn := node{e.to.n, e.to.call, toPath}
				// Block if source path is subsumed by must-not-flow source
				// AND target path is subsumed by must-not-flow target
				if pathSubsumes(e.from.path, fn.path) && pathSubsumes(e.to.path, tn.path) {
					edg := edge{from: fn, to: tn}
					constr := maxsat.HardClause(mayFlow(edg).Negation())
					constraints = append(constraints, constr)
					mnfCount++
				}
			}
		}
	}
	s.Logger.Debugf("added %d must-not-flow constraints", mnfCount)
	s.Logger.Debugf("computed %d constraints", len(constraints))

	// Find the optimal cost first
	prob := maxsat.New(constraints...)
	s.Logger.Debugf(
		"running callee summary inference MAXSAT solver for function %s...\n", g.Parent)
	startSolver := time.Now()
	model, optimalCost := prob.Solve()
	s.Logger.Debugf("... solver returned after %s", time.Since(startSolver))
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

	s.Logger.Debugf(
		"callee summary inference for function %s MAXSAT solver took %s\n",
		g.Parent, time.Since(start))

	return res, nil
}

// addCalleeMayFlowEdges adds edges of all callees to hardEdges and softEdges.
//
// If the callee has intra-procedural information, then its dataflow edges are added to known.
// If not, its most-general summary edges are added to unknown.
// The most-general summary is computed by the method specified by parameter via.
func addCalleeMayFlowEdges(
	s *dataflow.State, g *dataflow.SummaryGraph, via Method,
	hardEdges *[]edge, softEdges map[*dataflow.CallNode][]edge, unsoundness *Unsoundness,
	nodePathLen map[dataflow.GraphNode]int,
) {
	for _, calleeToCall := range g.Callees {
		for callee, call := range calleeToCall {
			calleeG, ok := s.FlowGraph.Summaries[callee]
			if !ok {
				panic(fmt.Errorf("no summary for callee %s", callee))
			}

			if calleeG.Constructed {
				edges := knownIntraEdges(s, calleeG, call, unsoundness, nodePathLen)
				*hardEdges = append(*hardEdges, edges...)
			} else {
				edges := mostGeneralEdges(calleeG, call, via, nodePathLen)
				softEdges[call] = edges
			}
		}
	}
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

// buildTransitivityConstrs returns a list of constraints representing the transitivity relation
// between edges over all nodes in the graph.
func buildTransitivityConstrs(s *dataflow.State, allEdges map[edge]struct{}) []maxsat.Constr {
	var transitiveConstrs []maxsat.Constr

	// Collect all nodes that appear in edges (these have path information)
	allNodes := make(map[node]struct{})
	for e := range allEdges {
		allNodes[e.from] = struct{}{}
		allNodes[e.to] = struct{}{}
	}

	// Field-sensitive transitivity: a->b1 ∧ b2->c ⇒ a->c where b1 subsumes b2
	for a := range allNodes {
		for b1 := range allNodes {
			for b2 := range allNodes {
				for c := range allNodes {
					if a != b1 && b2 != c && a != c && nodeSubsumes(b1, b2) {
						constr := maxsat.HardClause(
							mayFlow(edge{from: a, to: b1}).Negation(),
							mayFlow(edge{from: b2, to: c}).Negation(),
							mayFlow(edge{from: a, to: c}),
						)
						transitiveConstrs = append(transitiveConstrs, constr)
					}
				}
			}
		}
	}

	s.Logger.Debugf("transitivity: %d nodes, %d constraints", len(allNodes), len(transitiveConstrs))

	return transitiveConstrs
}

// nodeSubsumes returns true if a subsumes b.
// a subsumes b if the dataflow.GraphNodes match exactly and a's path is a prefix of b's path
// (i.e., b's path *has* a prefix of a's path).
//
// NOTE This is similar to the flowCovers function.
func nodeSubsumes(a, b node) bool {
	if a.n != b.n {
		return false
	}
	if a.call != b.call {
		return false
	}

	return pathSubsumes(a.path, b.path)
}

func pathSubsumes(a, b path) bool {
	aPath := a.String()
	bPath := b.String()
	// Empty path subsumes everything.
	if aPath == emptyPath {
		return true
	}

	return strings.HasPrefix(bPath, aPath)
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
// The parameter wantFlows is used to determine whether to enumerate field paths.
func mostGeneralEdges(
	g *dataflow.SummaryGraph, call *dataflow.CallNode, via Method,
	nodePathLen map[dataflow.GraphNode]int,
) []edge {
	if !(via == General || via == Types) {
		panic(fmt.Errorf("unsupported most-general method: %v", via))
	}

	flows, err := mostGeneralFlows(g, nodePathLen)
	if err != nil {
		panic(err)
	}
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
	path path
}

func (n node) String() string {
	pathStr := n.path.String()
	if n.call == nil {
		return graphNodeDesc(n.n) + pathStr
	}
	return fmt.Sprintf("%s_%s%s", graphNodeDesc(n.call), graphNodeDesc(n.n), pathStr)
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
		from: node{fl.from.node, call, fl.from.path},
		to:   node{fl.to.node, call, fl.to.path},
	}
}

func (e edge) String() string {
	return fmt.Sprintf("%s->%s", e.from.String(), e.to.String())
}

// addPrecision adds the access path length of a node in nodes that the node should have to
// nodePathLen.
//
// If two nodes in flows have the same access path length, it takes the greater of the two to
// maximize precision.
func addPrecision(nodePathLen map[dataflow.GraphNode]int, nodes []graphNode) {
	for _, node := range nodes {
		nodePathLen[node.node] = max(nodePathLen[node.node], node.path.len())
	}
}

// knownIntraEdges returns all the may-flow edges within a summary graph, scoped to a specific
// call site.
//
// It begins by tainting all input nodes, where the access path length is determined from
// nodePathLen (which in turn is from the must-not-flow node access paths), and then running the
// intra-procedural taint analysis.
// The intra-procedural taint analysis is a BFS over the intra-procedural flow graph g.
func knownIntraEdges(
	s *dataflow.State, g *dataflow.SummaryGraph, call *dataflow.CallNode,
	unsoundness *Unsoundness, nodePathLen map[dataflow.GraphNode]int,
) []edge {
	// Initialize queue with the input nodes.
	var queue []node
	g.ForAllNodes(func(n dataflow.GraphNode) {
		if skipNode(s, n, unsoundness) {
			return
		}

		switch n.(type) {
		case *dataflow.ParamNode, *dataflow.AccessGlobalNode, *dataflow.FreeVarNode:
			pl, ok := nodePathLen[n]
			if !ok || pl == 0 {
				// Input should be field-insensitive.
				from := node{n: n, call: call, path: newPath("", 0)}
				queue = append(queue, from)
				return
			}

			// Input should be field-sensitive: taint all input field paths with length up to pl.
			paths := leafPathsUpTo(n.Type(), pl)
			for _, path := range paths {
				from := node{n: n, call: call, path: path}
				queue = append(queue, from)
			}
		}
	})

	var edges []edge
	seen := make(map[node]struct{})

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var nexts []node
		if skipNode(s, cur.n, unsoundness) {
			continue
		}

		// Add intra-procedural edges.
		for next, edgeInfos := range cur.n.Out() {
			if skipNode(s, next, unsoundness) {
				continue
			}

			for _, edgeInfo := range edgeInfos {
				ns := nextNodes(cur, next, edgeInfo)
				// No matching access paths for this edge
				if len(ns) == 0 {
					continue
				}
				nexts = append(nexts, ns...)
			}
		}

		for _, next := range nexts {
			// Add the edge regardless of whether we've seen the node before
			e := edge{from: cur, to: next}
			edges = append(edges, e)

			if _, ok := seen[next]; ok {
				continue
			}
			seen[next] = struct{}{}
			queue = append(queue, next)
			// Update nodePathLen if next's path is more precise.
			nodePathLen[next.n] = max(nodePathLen[next.n], next.path.len())
		}
	}

	return edges
}

// nextNodes returns the nodes corresponding to access paths in next that match cur's access path.
func nextNodes(cur node, next dataflow.GraphNode, edgeInfo dataflow.EdgeInfo) []node {
	var nextNodes []node
	for inPath, outPaths := range edgeInfo.RelPath {
		for outPath := range outPaths {
			// NOTE In the dataflow/taint analysis, nodes and access paths are separate, so x.a and
			// x.b are the same dataflow.GraphNode but with different inPaths.
			// However, here each node has an access path, so x.a and x.b are distinct.

			// Logic for matching paths:
			if strings.HasPrefix(inPath, cur.path.String()) {
				p := newPath(outPath, maxPathLen)
				n := node{n: next, call: cur.call, path: p}
				nextNodes = append(nextNodes, n)
			}
		}
	}
	if len(edgeInfo.RelPath) == 0 || len(edgeInfo.RelPath) == 1 && edgeInfo.RelPath[""][""] {
		n := node{n: next, call: cur.call, path: cur.path}
		nextNodes = []node{n}
	}
	if len(edgeInfo.RelPath) == 1 && edgeInfo.RelPath["*"][""] {
		n := node{n: next, call: cur.call, path: path{}}
		nextNodes = []node{n}
	}

	return nextNodes
}

// unknownInterEdges returns the interprocedural may-flow edges between callers and their
// corresponding callees.
// It uses nodePathLen to determine the field-sensitivity of the nodes in each edge.
//
//gocyclo:ignore
func unknownInterEdges(
	s *dataflow.State, g *dataflow.SummaryGraph, nodePathLen map[dataflow.GraphNode]int,
) []edge {
	var res []edge

	// addEdge adds edg to res with field-sensitivity if required based on nodePathLen.
	// Updates nodePathLen as well.
	addEdge := func(edg edge) {
		from := edg.from.n
		to := edg.to.n
		pl := max(nodePathLen[from], nodePathLen[to])
		nodePathLen[from] = pl
		nodePathLen[to] = pl
		fromPaths := leafPathsUpTo(from.Type(), pl)
		toPaths := leafPathsUpTo(to.Type(), pl)
		for _, fromPath := range fromPaths {
			for _, toPath := range toPaths {
				fn := node{edg.from.n, edg.from.call, fromPath}
				tn := node{edg.to.n, edg.to.call, toPath}
				if pathSubsumes(fn.path, tn.path) || pathSubsumes(tn.path, fn.path) {
					e := edge{from: fn, to: tn}
					res = append(res, e)
				}
			}
		}
	}

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
			s.FlowGraph.BuildGraph(!s.Config.CheckIgnoresPredefined)

			// callee return -> call node
			for _, rets := range calleeSummary.Returns {
				for _, ret := range rets {
					e := edge{from: node{n: ret, call: call}, to: node{n: call, call: nil}}
					addEdge(e)
				}
			}

			// call arg -> callee param
			for _, arg := range call.Args() {
				for _, param := range calleeSummary.Params {
					if param.Index() == arg.Index() {
						// Create edge with same path for param
						e := edge{from: node{n: arg, call: nil}, to: node{n: param, call: call}}
						addEdge(e)
						break
					}
				}
			}

			// pointer-like callee param -> call arg
			// TODO maybe use more static analyses here?
			for _, param := range calleeSummary.Params {
				if isPointerLike(param.Type()) {
					for _, arg := range call.Args() {
						if param.Index() == arg.Index() {
							e := edge{from: node{n: param, call: call}, to: node{n: arg, call: nil}}
							addEdge(e)
							break
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
					e := edge{from: node{n: bv, call: nil}, to: node{n: fvNode, call: call}}
					addEdge(e)
					e = edge{from: node{n: fvNode, call: call}, to: node{n: bv, call: nil}}
					addEdge(e)
				}
			}
		}
	}

	return res
}

func unknownIntraEdges(
	s *dataflow.State, g *dataflow.SummaryGraph, unsoundness *Unsoundness,
	nodePathLen map[dataflow.GraphNode]int, knownIntra []edge,
) []edge {
	var res []edge
	// Collect all edges in the graph, not just those reachable from params.
	g.ForAllNodes(func(gn dataflow.GraphNode) {
		if skipNode(s, gn, unsoundness) {
			return
		}

		for next, edgeInfos := range gn.Out() {
			if skipNode(s, next, unsoundness) {
				continue
			}

			// Each gn corresponds to access paths.
			// The precision of each access path depends on the precision of gn and next.
			pl := max(nodePathLen[gn], nodePathLen[next])
			nodePathLen[gn] = pl
			nodePathLen[next] = pl

			paths := leafPathsUpTo(gn.Type(), pl)
			for _, path := range paths {
				n := node{n: gn, call: nil, path: path}
				for _, edgeInfo := range edgeInfos {
					nexts := nextNodes(n, next, edgeInfo)
					for _, next := range nexts {
						e := edge{from: n, to: next}
						if slices.Contains(knownIntra, e) {
							continue
						}
						res = append(res, e)
					}
				}
			}
		}
	})

	return res
}

func skipNode(s *dataflow.State, n dataflow.GraphNode, unsoundness *Unsoundness) bool {
	switch n.(type) {
	case *dataflow.BoundLabelNode:
		// TODO: re-enable once we support bound labels properly
		//closure := n.DestInfo().MakeClosure
		//if n.Graph().Parent != closure.Parent() {
		//	// If a bound label is created in a different function as its corresponding make
		//	// closure instruction, it means that there is no corresponding free variable
		//	// inside the closure for this bound label value. We do not support summary
		//	// nodes for closure-specific inputs/outputs other than bound and free
		//	// variables. It does not make sense to summarize closures with bound labels
		//	// because the input/output bound label value is not local to the closure: it is
		//	// scoped to the completely different function that allocated the bound label.
		//	pos := n.Position(s)
		//	if !slices.Contains(unsoundness.CheckFeatures.NonLocalBoundLabelUsages, pos) {
		//		unsoundness.CheckFeatures.NonLocalBoundLabelUsages =
		//			append(unsoundness.CheckFeatures.NonLocalBoundLabelUsages, pos)
		//	}
		//	s.Logger.Warnf(
		//		"cannot check summary where bound label closure is non-local. "+
		//			"label: %v in %v, closure: %v in %v",
		//		n, n.ParentName(), closure, closure.Parent())
		//	return true
		//}
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
		from := newSummaryNode(graphNode{e.from.n, e.from.path})
		to := newSummaryNode(graphNode{e.to.n, e.to.path})
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

// edgeSignature creates a semantic signature for an edge based on node types, indices, and paths.
// This allows matching edges across different call sites.
func edgeSignature(e edge) string {
	return fmt.Sprintf("%s->%s", nodeSignature(e.from), nodeSignature(e.to))
}

// nodeSignature creates a semantic signature for a node that is not specific to its enclosing
// (parent) function.
func nodeSignature(n node) string {
	var base string
	switch gn := n.n.(type) {
	case *dataflow.ParamNode:
		base = fmt.Sprintf("param:%d:%s", gn.Index(), gn.SsaNode().Name())
	case *dataflow.ReturnValNode:
		base = fmt.Sprintf("ret:%d", gn.Index())
	case *dataflow.FreeVarNode:
		base = fmt.Sprintf("fv:%s", gn.SsaNode().Name())
	default:
		panic(fmt.Errorf("invalid summary node: %v", n.n))
	}
	return base + n.path.String()
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

func isInputNode(n dataflow.GraphNode) bool {
	switch n.(type) {
	case *dataflow.ParamNode, *dataflow.BoundVarNode, *dataflow.AccessGlobalNode:
		return true
	default:
		return false
	}
}

func isOutputNode(n dataflow.GraphNode) bool {
	switch n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode, *dataflow.ReturnValNode:
		return true
	default:
		return false
	}
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
		s.Logger.Tracef("\t%+v\n", e.String())
	}
}
