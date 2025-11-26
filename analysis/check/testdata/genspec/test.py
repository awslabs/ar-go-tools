import z3

# func f(a *int, b *int, c *int) int {
# 	x := g(*a, *b)
# 	x += g(*a, *c)
# 	*c = x
# 	return x
# }

# func g(a int, b int) int {
# 	return a + b
# }

# Define universe
(
    Node,
    (
        f_param_a,
        f_param_b,
        f_param_c,
        f_call_g0,
        f_call_g0_arg_0,
        f_call_g0_arg_1,
        f_call_g1,
        f_call_g1_arg_0,
        f_call_g1_arg_1,
        f_ret,
        g_param_a,
        g_param_b,
        g_ret,
    ),
) = z3.EnumSort(
    "Node",
    [
        "f@param_a",
        "f@param_b",
        "f@param_c",
        "f@call_g0",
        "f@call_g0_arg_0",
        "f@call_g0_arg_1",
        "f@call_g1",
        "f@call_g1_arg_0",
        "f@call_g1_arg_1",
        "f@ret",
        "g@param_a",
        "g@param_b",
        "g@ret",
    ],
)
r = z3.Function("r", Node, Node, z3.BoolSort())

nodes = [
    f_param_a,
    f_param_b,
    f_param_c,
    f_call_g0,
    f_call_g0_arg_0,
    f_call_g0_arg_1,
    f_call_g1,
    f_call_g1_arg_0,
    f_call_g1_arg_1,
    f_ret,
    g_param_a,
    g_param_b,
    g_ret,
]

s = z3.Optimize()


# NOTE cannot encode this with quantifiers since z3 does not support MAXSAT with quantifiers
def assert_transitive(s, flows):
    for a, b in flows:
        for b, c in flows:
            s.add(z3.Implies(z3.And(r(a, b), r(b, c)), r(a, c)))


# Intra-procedural edges
intra = [
    (f_param_a, f_call_g0_arg_0),
    (f_param_b, f_call_g0_arg_1),
    (f_param_a, f_call_g1_arg_0),
    (f_param_c, f_call_g1_arg_1),
    (f_call_g0, f_param_c),
    (f_call_g1, f_param_c),
    (f_call_g0, f_ret),
    (f_call_g1, f_ret),
    (g_ret, f_call_g0),
    (g_ret, f_call_g1),
]
assert_transitive(s, intra)

# Unknown dataflow edges
unknown = [
    (g_param_a, g_ret),
    (g_param_b, g_ret),
    (g_param_a, g_param_b),
    (g_param_b, g_param_a),
]
assert_transitive(s, unknown)

want_summary = [
    (f_param_a, f_ret),
    (f_param_a, f_param_c),
    (f_param_b, f_ret),
    (f_param_b, f_param_c),
    (f_param_c, f_ret),
]


def transitive_closure(flows):
    res = set()
    for a, b in flows:
        for b, c in flows:
            res.add((a, b))
            res.add((b, c))
            res.add((a, c))
    return [(x, y) for x, y in res if x is not y]


transitive = transitive_closure(intra + unknown)
for a in nodes:
    for b in nodes:
        if a == b:
            continue
        if (a, b) in intra:
            s.add(r(a, b))
        elif (a, b) in unknown:
            s.add_soft(r(a, b))
        elif (a, b) in transitive:
            continue
        else:
            s.add(z3.Not(r(a, b)))

# Compute all edges needed to satisfy want_summary
for a, b in want_summary:
    s.add(r(a, b))

if s.check() != z3.sat:
    print("model is not sat!")
    exit(1)

m = s.model()
print("\nDataflow edges:")
for a in nodes:
    for b in nodes:
        if (a, b) in intra or (a, b) in want_summary or a == b:
            continue
        if z3.is_true(m.eval(r(a, b))):
            print(f"  {a} -> {b}")
