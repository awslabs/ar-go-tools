#!/usr/bin/env python3


"""
For the program:

func f(no *int, a *int, b *int) int {
    x := g(*a, *a, no)
    x += g(*a, *b, no)
    *b = x
    return x
}

func g(a int, b int, no *int) int {
    return a + b
}

Given intra-procedural dataflow results in `intra` and
the dataflow summary for function f that we want to check
in `want_summary`, this script infers what g's implementation
must be (in terms of dataflow edges) in order to satisfy f's
summary, while MINIMIZING the number of must-not-flow edges
(i.e., finding the most general valid summary of g).

For the summary of f: a->ret, a->b, b->ret,
the edges in g should be: a->b, b->a, a->ret, b->ret.

In order to satisfy the summary of f, the must-not-flow edges
for g are: no->a, no->b, no->ret, a->no, b->no.

The maximal must-not-flow edges for f are:
no->a, no->b, no->ret, a->no, a->ret, b->no, b->a.

It is fine for a to never flow to ret in g because
f@param_a flows to x via the first call to g, which
is enough to satisfy f's summary.

It is fine for a and b to flow to each other even though
this is impossible in practice because it does not change
the summary of f.
"""

import itertools
import z3


def main():
    # z3.set_param("sat.random_seed", 0)
    s = z3.Optimize()  # Use optimized solver for MAXSAT

    # Summary nodes for f (input and output)
    f_nodes = [
        "f@param_no",
        "f@param_a",
        "f@param_b",
        "f@ret",
    ]
    # Summary nodes for g (input and output)
    g_nodes = ["g@param_a", "g@param_b", "g@param_no", "g@ret"]

    # Intra-procedural edges (known)
    intra = [
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
    # Inter-procedural edges (known)
    inter = [
        ("f@call_g0_arg_0", "g@param_a"),
        ("f@call_g0_arg_1", "g@param_b"),
        ("f@call_g0_arg_2", "g@param_no"),
        ("f@call_g1_arg_0", "g@param_a"),
        ("f@call_g1_arg_1", "g@param_b"),
        ("f@call_g1_arg_2", "g@param_no"),
        ("g@ret", "f@call_g0"),
        ("g@ret", "f@call_g1"),
    ]
    known = intra + inter

    # Unknown dataflow edges (most-general summary of g):
    unknown = list(itertools.permutations(g_nodes, 2))

    # Summary we want to check
    want_summary = {
        ("f@param_a", "f@ret"),
        ("f@param_a", "f@param_b"),
        ("f@param_b", "f@ret"),
    }

    # Add constraints for known edges
    for a, b in known:
        s.add(may_flow(a, b))

    # Minimize must-not-flow unknown edges (maximize must-flow)
    # Sort for deterministic ordering
    for a, b in sorted(unknown):
        s.add_soft(may_flow(a, b), weight=1)

    # Add transitivity constraints for all nodes
    all_nodes = set()
    for a, b in known + unknown:
        all_nodes.add(a)
        all_nodes.add(b)

    for a, b, c in itertools.permutations(all_nodes, 3):
        s.add(z3.Implies(z3.And(may_flow(a, b), may_flow(b, c)), may_flow(a, c)))

    # Require want_summary must-not-flow edges to be true
    for a, b in set(itertools.permutations(f_nodes, 2)) - want_summary:
        s.add(z3.Not(may_flow(a, b)))

    # For each required summary edge, find all possible paths
    for src, dst in want_summary:
        paths = find_paths_through_unknown(src, dst, known, unknown)
        if paths:
            # At least one path must have all its unknown edges present
            # TODO not needed
            path_constraints = []
            for path_unknown_edges in paths:
                if path_unknown_edges:
                    path_constraints.append(
                        z3.And(*[may_flow(u, v) for u, v in path_unknown_edges])
                    )
            if path_constraints:
                s.add(z3.Or(*path_constraints))

    if s.check() != z3.sat:
        print("model is not sat!")
        exit(1)

    m = s.model()
    print(m)

    print("Must-not-flow dataflow edges for g:")
    for a, b in itertools.permutations(g_nodes, 2):
        if z3.is_false(m.eval(may_flow(a, b))):
            print(f"  {a} -/-> {b}")


def may_flow(a, b):
    return z3.Bool(f"r_{a}->{b}")


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


if __name__ == "__main__":
    main()
