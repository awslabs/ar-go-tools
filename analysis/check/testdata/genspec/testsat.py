#!/usr/bin/env python3

"""
Pure MaxSAT encoding for inferring g's dataflow summary.

Same problem as test.py but using standard MaxSAT format where all constraints
are CNF clauses (disjunctions of literals). This encoding could work with any
MaxSAT solver that accepts the DIMACS WCNF format.
"""

import itertools
import z3


def main():
    s = z3.Optimize()

    f_nodes = ["f@param_no", "f@param_a", "f@param_b", "f@ret"]

    intra_f = [
        ("f@param_a", "f@call_g0_arg_0"),
        ("f@param_a", "f@call_g0_arg_1"),
        ("f@param_no", "f@call_g0_arg_2"),
        ("f@param_a", "f@call_g1_arg_0"),
        ("f@param_b", "f@call_g1_arg_1"),
        ("f@param_no", "f@call_g1_arg_2"),
        ("f@call_g0", "f@param_b"),
        ("f@call_g1", "f@param_b"),
        ("f@call_g0", "f@ret"),
        ("f@call_g1", "f@ret"),
    ]
    inter = [
        ("f@call_g0_arg_0", "g0@param_a"),
        ("f@call_g0_arg_1", "g0@param_b"),
        ("f@call_g0_arg_2", "g0@param_no"),
        ("f@call_g1_arg_0", "g1@param_a"),
        ("f@call_g1_arg_1", "g1@param_b"),
        ("f@call_g1_arg_2", "g1@param_no"),
        ("g0@ret", "f@call_g0"),
        ("g1@ret", "f@call_g1"),
        ("g0@param_no", "f@param_no"),  # pointer
        ("g1@param_no", "f@param_no"),  # pointer
    ]
    known = intra_f + inter

    g_nodes = ["g@param_a", "g@param_b", "g@param_no", "g@ret"]
    # Unknown dataflow edges (most-general summary of g):
    g0_nodes = map(lambda n: n.replace("g", "g0"), g_nodes)
    g1_nodes = map(lambda n: n.replace("g", "g1"), g_nodes)
    intra_g0 = list(itertools.permutations(g0_nodes, 2))
    intra_g1 = list(itertools.permutations(g1_nodes, 2))
    unknown = intra_g0 + intra_g1

    # Summary we want to check
    want_summary = {
        ("f@param_a", "f@ret"),
        ("f@param_a", "f@param_b"),
        ("f@param_b", "f@ret"),
    }

    # Ensure g0 and g1 have identical summaries (same function)
    for a, b in intra_g0:
        a1 = a.replace("g0", "g1")
        b1 = b.replace("g0", "g1")
        s.add(may_flow(a, b) == may_flow(a1, b1))

    all_nodes = set()
    for a, b in known + unknown:
        all_nodes.add(a)
        all_nodes.add(b)
    for a, b in itertools.product(all_nodes, all_nodes):
        if a == b:
            continue
        if (a, b) in known:
            s.add(edge(a, b))
        elif (a, b) in unknown:
            s.add_soft(edge(a, b))
        else:
            s.add(z3.Not(edge(a, b)))

    # REACHABILITY (may-flow)

    # Edge implies may-flow: edge(a,b) → may_flow(a,b)
    # Converted to CNF: ¬edge(a,b) ∨ may_flow(a,b)
    for a, b in itertools.product(all_nodes, all_nodes):
        s.add(z3.Or(z3.Not(edge(a, b)), may_flow(a, b)))

    # may-flow is transitive
    # Transitivity: (may_flow(a,b) ∧ may_flow(b,c)) → may_flow(a,c)
    # Converted to CNF: ¬may_flow(a,b) ∨ ¬may_flow(b,c) ∨ may_flow(a,c)
    for a, b, c in itertools.product(all_nodes, repeat=3):
        if a != b and b != c:
            s.add(z3.Or(z3.Not(may_flow(a, b)), z3.Not(may_flow(b, c)), may_flow(a, c)))

    # Required summary edges
    for a, b in want_summary:
        s.add(may_flow(a, b))

    # Forbidden summary edges
    for a, b in set(itertools.permutations(f_nodes, 2)) - want_summary:
        s.add(z3.Not(may_flow(a, b)))

    # Transitivity requirement is only for the forward direction:
    #   If may_flow(a,b) and may_flow(b,c) are both true,
    #   then may_flow(a,c) must be true
    # It doesn't force may-flow edges to exist because the solver can
    # satisfy f's summary by directly setting the may_flow variables to true,
    # without requiring an actual path of edges to exist.
    #
    # What we really want is:
    #   If may_flow(a,c) must be true,
    #   then there must exist some b where may_flow(a,b) and may_flow(b,c)
    #
    # Finding at least one realizable path from an input (src)
    # node in the summary to an output (dst) node gives a witness
    # for the existential (b).
    #
    # Applies the Tseitin transformation to turn these constraints into CNF.
    for src, dst in want_summary:
        paths = find_paths_through_unknown(src, dst, known, unknown)
        if paths:
            path_vars = []
            for path_unknown_edges in paths:
                if path_unknown_edges:
                    # Auxiliary variable: p ↔ (e1 ∧ e2 ∧ ... ∧ en)
                    path_var = z3.Bool(f"path_{src}_{dst}_{len(path_vars)}")
                    path_vars.append(path_var)
                    # Forward direction: p → ei becomes ¬p ∨ ei
                    for u, v in path_unknown_edges:
                        s.add(z3.Or(z3.Not(path_var), may_flow(u, v)))
                    # Backward direction: (e1 ∧ ... ∧ en) → p becomes ¬e1 ∨ ... ∨ ¬en ∨ p
                    s.add(
                        z3.Or(
                            *[z3.Not(may_flow(u, v)) for u, v in path_unknown_edges],
                            path_var,
                        )
                    )
            if path_vars:
                # At least one path must be satisfied: p1 ∨ p2 ∨ ... ∨ pn
                s.add(z3.Or(*path_vars))

    if s.check() != z3.sat:
        print("model is not sat!")
        exit(1)

    m = s.model()

    print("Must-not-flow dataflow edges in g:")
    for a, b in sorted(unknown):
        if a.endswith("ret"):
            continue
        if z3.is_false(m.eval(may_flow(a, b))):
            print(f"  {a} -/-> {b}")

    print("Inferred summary of g:")
    for a, b in sorted(unknown):
        if a.endswith("ret"):
            continue
        if z3.is_true(m.eval(may_flow(a, b))):
            print(f"  {a} -> {b}")


def find_paths_through_unknown(src, dst, known, unknown):
    """
    Find all paths from src to dst, returning the unknown edges each path uses.

    Returns a list of paths, where each path is a list of unknown edges
    that must be present for that path to exist. Known edges are always
    present, so they're not included in the returned paths.
    """
    from collections import deque

    # Build adjacency lists
    known_graph = {}
    unknown_graph = {}
    for a, b in known:
        known_graph.setdefault(a, []).append(b)
    for a, b in unknown:
        unknown_graph.setdefault(a, []).append(b)

    # BFS to find all paths, tracking unknown edges used
    paths = []
    queue = deque([(src, [], [])])  # (current_node, unknown_edges_used, visited)

    while queue:
        node, unknown_used, visited = queue.popleft()

        if node == dst:
            paths.append(unknown_used)
            continue

        if node in visited:
            continue
        visited = visited + [node]

        # Follow known edges
        for next_node in known_graph.get(node, []):
            queue.append((next_node, unknown_used, visited))

        # Follow unknown edges
        for next_node in unknown_graph.get(node, []):
            queue.append((next_node, unknown_used + [(node, next_node)], visited))

    return paths


def may_flow(a, b):
    return z3.Bool(f"mayflow_{a}->{b}")


def edge(a, b):
    return z3.Bool(f"edge_{a}->{b}")


if __name__ == "__main__":
    main()
