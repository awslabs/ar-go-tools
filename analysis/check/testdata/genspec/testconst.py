#!/usr/bin/env python3


"""
For the program:

func f(a *int, b *int, c *int) int {
    x := g(*a, *b)
    x += g(*a, *c)
    *c = x
    return x
}

func g(a int, b int) int {
    return a + b
}

Given intra-procedural dataflow results in `intra` and
the dataflow summary for function f that we want to check
in `want_summary`, this script computes the maximum set
of unknown dataflow edges that must hold in the rest of
the program in order to satisfy the dataflow summary.

For the summary of f: a->ret, a->c, b->ret, b->c, c->ret,
the edges in g should be: a->b, b->a, a->ret, b->ret.
It is fine for a and b to flow to each other even though
this is impossible in practice because it does not change
the summary of f.
"""

import z3


def main():
    s = z3.Optimize()  # Use optimized solver for MAXSAT

    # Intra-procedural edges
    intra = [
        ("f@param_a", "f@call_g0_arg_0"),
        ("f@param_b", "f@call_g0_arg_1"),
        ("f@param_a", "f@call_g1_arg_0"),
        ("f@param_c", "f@call_g1_arg_1"),
        ("f@call_g0", "f@param_c"),
        ("f@call_g1", "f@param_c"),
        ("f@call_g0", "f@ret"),
        ("f@call_g1", "f@ret"),
        ("g@ret", "f@call_g0"),
        ("g@ret", "f@call_g1"),
    ]

    # Unknown dataflow edges:
    # We want to maximize the number of these edges that are true
    # (must have dataflow to satisfy want_summary)
    unknown = [
        ("g@param_a", "g@ret"),
        ("g@param_b", "g@ret"),
        ("g@param_a", "g@param_b"),
        ("g@param_b", "g@param_a"),
    ]

    # Summary we want to check
    want_summary = [
        ("f@param_a", "f@ret"),
        ("f@param_a", "f@param_c"),
        ("f@param_b", "f@ret"),
        ("f@param_b", "f@param_c"),
        ("f@param_c", "f@ret"),
    ]

    # Compute which edges could potentially be reachable
    potentially_reachable = transitive_closure(intra + unknown)

    # Add constraints only for potentially reachable edges
    for a, b in potentially_reachable:
        # We know that there is dataflow for the intra-procedural edges
        if (a, b) in intra:
            s.add(reach(a, b))
        # We know that there may be dataflow for the unknown edges:
        # maximize the unknown dataflows
        elif (a, b) in unknown:
            s.add_soft(reach(a, b))

    # Add transitivity constraints only for potentially reachable edges
    for a, b in potentially_reachable:
        for c, d in potentially_reachable:
            if b == c:
                expr = z3.Implies(
                    z3.And(reach(a, b), reach(c, d)),
                    reach(a, d),
                )
                s.add(expr)

    # Require want_summary edges to be true
    for a, b in want_summary:
        s.add(reach(a, b))

    if s.check() != z3.sat:
        print("model is not sat!")
        exit(1)

    m = s.model()
    print("Unknown dataflow edges:")
    for a, b in unknown:
        if z3.is_true(m.eval(reach(a, b))):
            print(f"  {a} -> {b}")


def reach(a, b):
    return z3.Bool(f"r_{a}->{b}")


def transitive_closure(edges):
    """Computes the transitive closure of a set of edges"""
    res = set(edges)
    changed = True
    while changed:
        changed = False
        for a, b in list(res):
            for c, d in list(res):
                if b == c and (a, d) not in res:
                    res.add((a, d))
                    changed = True
    return res


if __name__ == "__main__":
    main()
