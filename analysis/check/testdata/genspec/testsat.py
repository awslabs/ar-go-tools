#!/usr/bin/env python3

"""
Pure MaxSAT encoding for inferring g's dataflow summary.

Same problem as test.py but using standard MaxSAT format where all constraints
are CNF clauses (disjunctions of literals). This encoding could work with any
MaxSAT solver that accepts DIMACS WCNF format.

Encoding structure:
1. Variables: reach(a,b) for each potential dataflow edge a→b
2. Hard clauses (must be satisfied):
   - Unit clauses: reach(a,b) for known edges
   - Ternary clauses: ¬reach(a,b) ∨ ¬reach(b,c) ∨ reach(a,c) for transitivity
   - Unit clauses: reach(a,b) for required summary edges
   - Negative unit clauses: ¬reach(a,b) for forbidden summary edges
   - Path existence via Tseitin transformation (see below)
3. Soft clauses (maximize satisfied):
   - ¬reach(a,b) for each unknown edge (weight=1)

Tseitin transformation for path constraints:
To encode "at least one path must exist" in CNF, we convert the DNF formula
(path1 ∨ path2 ∨ ...) where each path is (e1 ∧ e2 ∧ ...) into CNF:
- Introduce auxiliary variable p_i for each path
- Encode p_i ↔ (e1 ∧ e2 ∧ ...):
  - Forward: p_i → e_j becomes ¬p_i ∨ e_j (one clause per edge)
  - Backward: (e1 ∧ ... ∧ e_n) → p_i becomes ¬e1 ∨ ... ∨ ¬e_n ∨ p_i
- Add clause: p_1 ∨ p_2 ∨ ... (at least one path exists)
"""

import itertools
import z3


def main():
    s = z3.Optimize()

    g_nodes = ["g@param_a", "g@param_b", "g@param_no", "g@ret"]
    f_nodes = ["f@param_no", "f@param_a", "f@param_b", "f@ret"]

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
    unknown = list(itertools.permutations(g_nodes, 2))
    # Remove edges from return nodes (returns are outputs, no outgoing edges)
    unknown = [(a, b) for a, b in unknown if not a.endswith("@ret")]

    want_summary = {
        ("f@param_a", "f@ret"),
        ("f@param_a", "f@param_b"),
        ("f@param_b", "f@ret"),
    }

    all_nodes = set()
    for a, b in known + unknown:
        all_nodes.add(a)
        all_nodes.add(b)

    # === HARD CLAUSES ===

    # Known edges: unit clauses reach(a,b)
    for a, b in known:
        s.add(reach(a, b))

    # Transitivity: (reach(a,b) ∧ reach(b,c)) → reach(a,c)
    # Converted to CNF: ¬reach(a,b) ∨ ¬reach(b,c) ∨ reach(a,c)
    for a, b, c in itertools.permutations(all_nodes, 3):
        s.add(z3.Or(z3.Not(reach(a, b)), z3.Not(reach(b, c)), reach(a, c)))

    # Required summary edges: unit clauses reach(a,b)
    for a, b in want_summary:
        s.add(reach(a, b))

    # Forbidden summary edges: negative unit clauses ¬reach(a,b)
    for a, b in set(itertools.permutations(f_nodes, 2)) - want_summary:
        s.add(z3.Not(reach(a, b)))

    # Path existence constraints using Tseitin transformation
    # For each required summary edge, ensure at least one valid path exists
    # through the call graph (combining known and unknown edges)
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
                        s.add(z3.Or(z3.Not(path_var), reach(u, v)))
                    # Backward direction: (e1 ∧ ... ∧ en) → p becomes ¬e1 ∨ ... ∨ ¬en ∨ p
                    s.add(
                        z3.Or(
                            *[z3.Not(reach(u, v)) for u, v in path_unknown_edges],
                            path_var,
                        )
                    )
            if path_vars:
                # At least one path must be satisfied: p1 ∨ p2 ∨ ... ∨ pn
                s.add(z3.Or(*path_vars))

    # === SOFT CLAUSES ===

    # Maximize must-not-flow edges (minimize unknown edges)
    # Each soft clause ¬reach(a,b) with weight=1
    for a, b in sorted(unknown):
        s.add_soft(z3.Not(reach(a, b)), weight=1)

    if s.check() != z3.sat:
        print("model is not sat!")
        exit(1)

    m = s.model()
    print("Must-not-flow dataflow edges for g:")
    for a, b in unknown:
        if z3.is_false(m.eval(reach(a, b))):
            print(f"  {a} -/-> {b}")


def reach(a, b):
    return z3.Bool(f"r_{a}->{b}")


def find_paths_through_unknown(src, dst, known, unknown):
    """
    Find all paths from src to dst through the call graph.

    Returns a list of paths, where each path is a list of unknown edges
    that must be present for that path to exist. Known edges are always
    present, so they're not included in the returned paths.
    """
    from collections import deque

    known_graph = {}
    unknown_graph = {}
    for a, b in known:
        known_graph.setdefault(a, []).append(b)
    for a, b in unknown:
        unknown_graph.setdefault(a, []).append(b)

    paths = []
    queue = deque([(src, [], [])])

    while queue:
        node, unknown_used, visited = queue.popleft()

        if node == dst:
            paths.append(unknown_used)
            continue

        if node in visited:
            continue
        visited = visited + [node]

        for next_node in known_graph.get(node, []):
            queue.append((next_node, unknown_used, visited))

        for next_node in unknown_graph.get(node, []):
            queue.append((next_node, unknown_used + [(node, next_node)], visited))

    return paths


if __name__ == "__main__":
    main()
