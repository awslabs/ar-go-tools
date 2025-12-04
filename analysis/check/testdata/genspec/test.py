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

We are given a candidate summary for f that we want to check is sound:
a->ret, a->b, b->ret.

We know that this candidate summary is sound if g does not produce
any dataflow edges that are not in the candidate summary.

The summary edges for f that are not in the candidate summary are:
  f@param_a->f@param_no
  f@param_no->f@param_a
  f@param_no->f@ret
  f@param_b->f@param_a
  f@param_no->f@param_b
  f@param_b->f@param_no

There are two possible summaries for g that do not violate the
must-not-flow edges of the candidate summary:

  Solution 1:
  g@param_a -> g@param_b
  g@param_a -> g@ret
  g@param_b -> g@param_a
  g@param_b -> g@ret

  g@param_a -/-> g@param_no
  g@param_b -/-> g@param_no
  g@param_no -/-> g@param_a
  g@param_no -/-> g@param_b
  g@param_no -/-> g@ret

  Solution 2:
  g@param_a -> g@param_b
  g@param_b -> g@param_a
  g@param_no -> g@param_a
  g@param_no -> g@param_b

  g@param_a -/-> g@param_no
  g@param_a -/-> g@ret
  g@param_b -/-> g@param_no
  g@param_b -/-> g@ret
  g@param_no -/-> g@ret

Solution 2 is interesting because it technically does not satisfy
the candidate summary for f, but it is still valid because it does
not produce any flows in f that violate the must-not-flow requirements
of the candidate summary. For example, even if param `no` in g flows to
param a in g, there is no way to get a flow from `no` to any output node
in f because there are no inter-procedural edges from any of g's parameters
other than `no` because they are not pointer-like.

If we check the must-not-flow edges in Solution 2, we see that they are
trivially unsatisfiable because, for example, parameter a does flow to the
return.

This uses a pure MAXSAT encoding in CNF which makes it portable to solvers
other than z3.
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
        ("f@call_g0_arg_2", "f@param_no"),
        ("f@param_a", "f@call_g1_arg_0"),
        ("f@param_b", "f@call_g1_arg_1"),
        ("f@param_no", "f@call_g1_arg_2"),
        ("f@call_g1_arg_2", "f@param_no"),
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
        ("g0@param_no", "f@call_g0_arg_2"),  # pointer
        ("g1@param_no", "f@call_g1_arg_2"),  # pointer
    ]
    known = intra_f + inter

    g_nodes = ["g@param_a", "g@param_b", "g@param_no", "g@ret"]
    # Unknown dataflow edges (most-general summary of g):
    g0_nodes = map(lambda n: n.replace("g", "g0"), g_nodes)
    g1_nodes = map(lambda n: n.replace("g", "g1"), g_nodes)
    intra_g0 = list(most_general_summary(g0_nodes))
    intra_g1 = list(most_general_summary(g1_nodes))
    unknown = intra_g0 + intra_g1

    # Ensure g0 and g1 have identical summaries (same function)
    # a == b is equivalent to (a → b) ∧ (b → a)
    # Which in CNF is: (¬a ∨ b) ∧ (¬b ∨ a)
    for a, b in intra_g0:
        a1 = a.replace("g0", "g1")
        b1 = b.replace("g0", "g1")
        s.add(z3.Or(z3.Not(may_flow(a, b)), may_flow(a1, b1)))
        s.add(z3.Or(z3.Not(may_flow(a1, b1)), may_flow(a, b)))

    # Add constraints for known edges
    for a, b in known:
        s.add(may_flow(a, b))

    # Minimize must-not-flow unknown edges (maximize may-flow)
    for a, b in unknown:
        s.add_soft(may_flow(a, b))

    # may-flow is transitive for all nodes
    all_nodes = set()
    for a, b in known + unknown:
        all_nodes.add(a)
        all_nodes.add(b)
    # Transitivity: (may_flow(a,b) ∧ may_flow(b,c)) → may_flow(a,c)
    # Converted to CNF: ¬may_flow(a,b) ∨ ¬may_flow(b,c) ∨ may_flow(a,c)
    for a, b, c in itertools.product(all_nodes, repeat=3):
        if a != b and b != c and a != c:
            s.add(z3.Or(z3.Not(may_flow(a, b)), z3.Not(may_flow(b, c)), may_flow(a, c)))

    # Summary we want to check
    want_summary = {
        ("f@param_a", "f@ret"),
        ("f@param_a", "f@param_b"),
        ("f@param_b", "f@ret"),
    }

    # Require want_summary must-not-flow edges to be true
    for a, b in set(most_general_summary(f_nodes)) - want_summary:
        s.add(z3.Not(may_flow(a, b)))

    if s.check() != z3.sat:
        print("model is not sat!")
        exit(1)

    m = s.model()

    print("Must-not-flow dataflow edges in g:")
    for a, b in sorted(unknown):
        if z3.is_false(m.eval(may_flow(a, b))):
            print(f"  {a} -/-> {b}")

    print("Inferred summary of g:")
    for a, b in sorted(unknown):
        if z3.is_true(m.eval(may_flow(a, b))):
            print(f"  {a} -> {b}")


def most_general_summary(nodes):
    return filter(lambda e: not e[0].endswith("ret"), itertools.permutations(nodes, 2))


def may_flow(a, b):
    return z3.Bool(f"mayflow_{a}->{b}")


if __name__ == "__main__":
    main()
