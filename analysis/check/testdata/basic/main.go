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

package main

import (
	"fmt"
	"math/rand"
	"strconv"
)

func Source() string {
	return "Hello " + strconv.Itoa(rand.Intn(100)) + " world!"
}

func Sink(_ string) {}

func singleArgIntraOut(x int) int {
	return x
}

func singleArgInterNone(x int) int {
	return noop(x)
}

func noop(int) int {
	return 0
}

func twoArgIntraInout(x *int, y *int) {
	*y = *x
}

func twoArgInterInout(x *int, y *int) {
	setmem(y, *x)
}

func setmem(dst *int, src int) {
	*dst = src
}

var global int

func singleArgIntraGlobal(x int) int {
	global = x
	return global
}

func singleArgInterGlobal(x int) int {
	setmem(&global, x)
	return global
}

func testSingleArgIntraOut() {
	fmt.Println(singleArgIntraOut(1))
}

func testSingleArgInterNone() {
	fmt.Println(singleArgInterNone(1))
}

func testTwoArgIntraInout() {
	x := 1
	y := -1
	twoArgIntraInout(&x, &y)
	fmt.Println(y)
}

func testTwoArgInterInout() {
	x := 1
	y := -1
	twoArgInterInout(&x, &y)
	fmt.Println(y)
}

func testSingleArgIntraGlobal() {
	fmt.Println(singleArgIntraGlobal(1)) // 1
	fmt.Println(global)                  // 1
}

func testSingleArgInterGlobal() {
	fmt.Println(singleArgInterGlobal(2)) // 2
	fmt.Println(global)                  // 2
}

func twoArgInterBool(x, y int) bool {
	return gt(x, y, 0)
}

func gt(x, y, z int) bool {
	// NOTE x does not flow to the return value here because it's the condition of an if-statement,
	// but y does flow to the return value.
	//
	// This is a weird artifact of Go's SSA representation:
	// func gt(x int, y int, z int) bool:
	// 0:                                                                entry P:0 S:2
	// 	t0 = x > z                                                         bool
	// 	if t0 goto 2 else 1
	// 1:                                                            binop.rhs P:1 S:1
	// 	t1 = y > z                                                         bool
	// 	jump 2
	// 2:                                                           binop.done P:2 S:0
	// 	t2 = phi [0: true:bool, 1: t1] #||                                 bool
	// 	return t2

	return x > z || y > z
}

func testTwoArgInterBool() {
	fmt.Println(twoArgInterBool(1, 2)) // true
}

func twoArgInter(x, y int) int {
	return plus(x, y, 3)
}

func plus(x, y, z int) int {
	return x + y + z
}

func testTwoArgInter() {
	fmt.Println(twoArgInter(1, 2)) // 6
}

func threeArgInter(no *int, a *int, b *int) int {
	x := add2(*a, *a, no)
	x += add2(*a, *b, no)
	*b = x
	return x
}

func add2(a int, b int, no *int) int {
	return a + b
}

func testThreeArgInter() {
	x, y, z := 0, 1, 2
	res := threeArgInter(&x, &y, &z)
	fmt.Println(res) // 5
}

func threeArgInterDiffCallees(no, a, b *int) int {
	x := add1(*a, *a, no)
	y := add2(*a, *b, no)
	*b = x + y
	return x + y
}

func add1(a int, b int, no *int) int {
	return a + 1
}

func testThreeArgInterDiffCallees() {
	x, y, z := 0, 1, 2
	res := threeArgInterDiffCallees(&x, &y, &z)
	fmt.Println(res) // 5
}

type container struct {
	field *data
	other *data
}

type data struct {
	value int
}

func propagateFields(src, dst *container) {
	dst.field = addVals(src.field, src.other)
	dst.other = addVals(src.other, src.field)
}

func addVals(a, b *data) *data {
	return &data{value: a.value + b.value}
}

func testFieldPropagation() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFields(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
	// x.field:0 x.other:1, y.field:1 y.other:1
}

func aliasPtr(out **int, a, b *int) {
	setPtsB(out, a, b)
}

func setPtsB(out **int, a, b *int) {
	*out = b
}

func testMutatePtr() {
	outv, a, b := new(int), new(int), new(int)
	*a = 0
	*b = -5
	outv = a
	aliasPtr(&outv, a, b)
	fmt.Println(*outv) // -5
}

type state struct {
	acc   int
	count int
}

func sharedMutation(a, b *int, shared *state) int {
	modify(a, shared)
	modify(b, shared)
	return shared.acc
}

func modify(val *int, s *state) {
	s.acc += *val
}

func testSharedMutation() {
	a, b := 0, 1
	st := &state{2, 3}
	res := sharedMutation(&a, &b, st)
	fmt.Println(res) // 3
}

// mixedCalleeSoundness calls two different callees on disjoint inputs: modify (whose checked
// summary is unsound due to a known alias-analysis false-positive reverse leak, see sharedMutation)
// and add1 (whose checked summary is sound). This isolates the Recursive method's must-not-flow
// pruning: must-not-flows that can only be realized through modify's call site must remain
// unproven, while must-not-flows that can only be realized through add1's call site -- unrelated to
// modify entirely -- must be pruned despite modify being unsound.
func mixedCalleeSoundness(a, b *int, shared *state) int {
	modify(a, shared)
	no := 0
	return add1(*b, *b, &no)
}

func testMixedCalleeSoundness() {
	a, b := 0, 1
	shared := &state{2, 3}
	res := mixedCalleeSoundness(&a, &b, shared)
	fmt.Println(res)
}

func addPtrs(x, y *int) *int {
	sum := *x + *y
	return &sum
}

func storePtr(x, y *int) int {
	z := addPtrs(x, y)
	x = z
	return *x
}

func testStorePtr() {
	a, b := 0, 1
	res := storePtr(&a, &b)
	fmt.Println("testStorePtr", res)
}

func aliasNoop(x, y *int) {
	x = y
}

func testAliasInterNone() {
	x, y := new(int), new(int)
	*x = 0
	*y = 2
	aliasNoop(y, x)
	*x++
	fmt.Println("testAliasInterNone", *y) // 2
	// Does not print 1 because aliasNoop aliases a local copy of y and x, not the actual arguments
}

func alias(x ***int, y **int) {
	*x = y
}

func testAliasInter() {
	x, y := new(int), new(int)
	*x = 0
	*y = 2
	yp := &y
	alias(&yp, &x)
	*x++
	fmt.Println("testAliasInter", **yp) // 1
}

func writeStructPtr(x, y *state) {
	*x = *y
	// x.acc = y.acc
	// x.count = y.count
}

func testWriteStructPtr() {
	x := &state{}
	y := &state{acc: 1, count: 1}
	writeStructPtr(x, y)
	fmt.Println("testWriteStructPtr", x.count) // 1
}

// writeStructPtrWithExtra mirrors writeStructPtr's known alias-analysis false positive (x -> y
// falsely reported unproven) but adds a third, unrelated pointer parameter z that is only ever read
// (never written, never aliased with x or y). This is a regression test for whether
// unprovenFlowsAfterCalleeCheck forces only the callee's own genuinely unproven edges true, rather
// than every edge belonging to the callee.
func writeStructPtrWithExtra(x, y *state, z *int) int {
	*x = *y
	return *z
}

func callerOfWriteStructPtrWithExtra(a, b *state, c *int) int {
	return writeStructPtrWithExtra(a, b, c)
}

func testCallerOfWriteStructPtrWithExtra() {
	a := &state{}
	b := &state{acc: 1, count: 1}
	c := 5
	res := callerOfWriteStructPtrWithExtra(a, b, &c)
	fmt.Println(a.count, res)
}

// twoCallSitesOfWriteStructPtrWithExtra calls writeStructPtrWithExtra at two call sites with
// disjoint arguments, mirroring sharedMutation's two-call-site pattern. This is a regression test
// for combining buildCalleeSummaryConstrs (which forces both call sites to share an identical
// inferred summary) with edgesForUnsoundCalleeFlows's per-call-site resolution via
// call.CalleeSummary: each call site has its own distinct CalleeSummary graph object, so resolving
// the shared callee's UnprovenMustNotFlows must correctly match edges at both sites, not just one.
func twoCallSitesOfWriteStructPtrWithExtra(a, b, p, q *state, c, d *int) int {
	r1 := writeStructPtrWithExtra(a, b, c)
	r2 := writeStructPtrWithExtra(p, q, d)
	return r1 + r2
}

func testTwoCallSitesOfWriteStructPtrWithExtra() {
	a, b := &state{}, &state{acc: 1, count: 1}
	p, q := &state{}, &state{acc: 2, count: 2}
	c, d := 5, 6
	res := twoCallSitesOfWriteStructPtrWithExtra(a, b, p, q, &c, &d)
	fmt.Println(a.count, p.count, res)
}

func writeToClosed(x, y int) int {
	f := func() int {
		y = x
		return x
	}
	return f() + f()
}

func testClosure() {
	res := writeToClosed(0, -5)
	fmt.Println("testClosure", res) // 0
}

// leakAcrossClosureCalls is writeToClosed's counterpart, where the closure really does copy its
// captured y into x -- but reads x into the return value *before* that write. Within a single call y
// therefore does not reach the return value, so the closure's own flows are {x -> !ret 0, y -> x}
// and not y -> !ret 0. Calling it twice makes y -> !ret 0 real anyway: the first call stores y into
// the captured x, and the second call returns it.
//
// This is a regression test for composing a callee's own summary edges. An encoding that treats
// y -> x and x -> !ret 0 as independent will infer a closure summary containing both, find that the
// real closure satisfies it, and report the summary x -> !ret 0 as sound even though y reaches the
// return value. Composing them makes the two edges mutually exclusive, so no inferred summary
// covers the closure's real behavior and the check correctly comes back unsound.
func leakAcrossClosureCalls(x, y int) int {
	f := func() int {
		r := x
		x = y
		return r
	}
	return f() + f()
}

func testLeakAcrossClosureCalls() {
	res := leakAcrossClosureCalls(1, -5)
	fmt.Println("testLeakAcrossClosureCalls", res) // 1 + (-5)
}

func nestedClosures(x, y *int) *int {
	bv := *y
	outer := func(z *int) *int {
		inner := func() *int {
			return z
		}
		res := *inner() + bv
		return &res
	}
	return outer(x)
}

func testNestedClosures() {
	a, b := 1, 2
	res := nestedClosures(&a, &b)
	fmt.Println("testNestedClosures", *res) // 3
}

func closureShared(x, y *int) *int {
	f1 := func() *int {
		*x = *y
		return x
	}
	f2 := func() *int {
		return y
	}
	f1()
	return f2()
}

func testClosureShared() {
	a, b := 1, 2
	res := closureShared(&a, &b)
	fmt.Println("testClosureShared", *res) // 2
}

func noFlowClosure(x, y *int) *int {
	f := func() *int {
		z := 42
		return &z
	}
	return f()
}

func testNoFlowClosure() {
	a, b := 1, 2
	res := noFlowClosure(&a, &b)
	fmt.Println("testNoFlowClosure", *res) // 42
}

func nestedClosuresInvalid(x, y *int) *int {
	outer := func() *int {
		inner := func() *int {
			*x = *x + *y // x is a non-local bound label which cannot be soundly checked
			return x
		}
		return inner()
	}
	return outer()
}

func testNestedClosuresInvalid() {
	a, b := 1, 2
	res := nestedClosuresInvalid(&a, &b)
	fmt.Println("testNestedClosuresInvalid", *res) // 3
}

func sourceCaller() string {
	return Source()
}

func testSummarizeSourceCallerUnsound() {
	s := sourceCaller()
	Sink(s)
}

func sinkCaller(x string) {
	Sink(x)
}

func testSummarizeSinkCallerUnsound() {
	s := sourceCaller()
	sinkCaller(s)
}

// multiFieldReceiver has several fields, mirroring a struct with multiple exported config-like
// fields (e.g. aws-sdk-go's client.Client), to reproduce a duplication bug in
// UnprovenMustNotFlows when Want has several field-sensitive entries with the same (!receiver)
// base.
type multiFieldReceiver struct {
	fieldA string
	fieldB string
	fieldC string
	fieldD string
}

// multiFieldResult mirrors a struct with many fields set from many different inputs so the helper's
// own summary is itself non-trivial.
type multiFieldResult struct {
	outA string
	outB string
	outC string
	outD string
	outX string
	outY string
	outZ string
}

// multiFieldMethod calls a helper and writes into out; used with a Want that omits some real
// flows, forcing the checker to recurse and report several receiver-sourced must-not-flows.
func (r *multiFieldReceiver) multiFieldMethod(
	argX string, argY string, argZ string, out *multiFieldReceiver) string {

	res := multiFieldHelper(r.fieldA, r.fieldB, r.fieldC, r.fieldD, argX, argY, argZ)
	out.fieldA = res.outA
	out.fieldB = res.outB
	return res.outA + res.outB + res.outC + res.outD + res.outX + res.outY + res.outZ
}

func multiFieldHelper(a, b, c, d, x, y, z string) *multiFieldResult {
	res := &multiFieldResult{}
	if len(a) > 0 {
		res.outA = a
		res.outX = x
	} else {
		res.outB = b
		res.outY = y
	}
	if len(c) > 0 {
		res.outC = c
		res.outZ = z
	} else {
		res.outD = d
	}
	return res
}

type slots struct {
	A string
	B string
}

func joinSlots(a, b string) slots {
	return slots{A: a + b, B: b + a}
}

// coarsenedOutParam is a minimal version of multiFieldMethod's shape, and exercises the coarsening
// pass. The summary names src's fields, which makes the whole analysis field-sensitive, but names out
// only as a whole. The body writes two distinct fields of out, so the flow graph gets out.A and out.B
// vertices -- both dead ends, since neither is read again, and both indistinguishable to the encoding,
// which never refers to out at a field. Coarsening merges them back into out.
//
// This is the shape where the merge must not go too far: out is also an *input* of the function, so
// the vertex it collapses onto already exists with outgoing edges. Merging into that one would splice
// the dead ends onto out's successors and chain unrelated callee hypotheses, which is what
// coarserVertex's occupancy guard prevents.
func coarsenedOutParam(src *slots, out *slots) string {
	r := joinSlots(src.A, src.B)
	out.A = r.A
	out.B = r.B
	return r.A + r.B
}

func testCoarsenedOutParam() {
	src := &slots{A: "a", B: "b"}
	out := &slots{}
	res := coarsenedOutParam(src, out)
	fmt.Println("testCoarsenedOutParam", res, out.A, out.B)
}

// negateInt returns -x, so x really does flow to the return value. The read analysis has to recognize
// an arithmetic UnOp as reading its operand; a switch that only handles pointer dereference and
// channel receive does not, and then "proves" this flow absent.
func negateInt(x, y int) int {
	return -x
}

// toAny returns x boxed in an interface, so x really does flow to the return value. The read analysis
// has to recognize MakeInterface as reading its operand.
func toAny(x string) any {
	return x
}

func testReadInstructionKinds() {
	fmt.Println("testReadInstructionKinds", negateInt(1, 2), toAny("a"))
}

func testMultiFieldReceiver() {
	r := &multiFieldReceiver{fieldA: "a", fieldB: "b", fieldC: "c", fieldD: "d"}
	out := &multiFieldReceiver{}
	_ = r.multiFieldMethod("x", "y", "z", out)
}

func main() {
	testSingleArgIntraOut()
	testSingleArgInterNone()
	testTwoArgIntraInout()
	testTwoArgInterInout()
	testSingleArgIntraGlobal()
	testSingleArgInterGlobal()
	testTwoArgInterBool()
	testTwoArgInter()
	testThreeArgInter()
	testThreeArgInterDiffCallees()
	testFieldPropagation()
	testSharedMutation()
	testMixedCalleeSoundness()
	testCallerOfWriteStructPtrWithExtra()
	testTwoCallSitesOfWriteStructPtrWithExtra()
	testStorePtr()
	testMutatePtr()
	testAliasInterNone()
	testAliasInter()
	testWriteStructPtr()
	testClosure()
	testLeakAcrossClosureCalls()
	testNestedClosures()
	testClosureShared()
	testNoFlowClosure()
	testNestedClosuresInvalid()
	testSummarizeSourceCallerUnsound()
	testSummarizeSinkCallerUnsound()
	testMultiFieldReceiver()
	testReadInstructionKinds()
	testCoarsenedOutParam()
}
