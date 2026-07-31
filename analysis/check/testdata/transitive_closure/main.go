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

func foo0(a string, b string) string {
	return a + b
}

func fooTop(s string) string {
	return foo0(s, s)
}

type contents struct {
	a string
	b string
	c string
}

func bar(s string) string {
	s2 := fmt.Sprintf("generate-%d", rand.Int())
	c := contents{
		a: s,
		b: s2,
		c: "hello",
	}
	res := fooTop(c.c)
	return res + c.c
}

func baz(s string) string {
	b := "ok"
	a := "ok"
	c := strconv.Itoa(rand.Int())
	for {
		a = b
		b = c
		if rand.Int()%2 == 0 {
			break
		}
	}
	return a
}

func zoo(c contents) string {
	return fooTop(c.a) + c.b
}

// copyString demonstrates flow from one parameter to another
func copyString(a *string, b *string) {
	*a = *b
}

// swapStrings demonstrates bidirectional flow between parameters
func swapStrings(a *string, b *string) {
	temp := *a
	*a = *b
	*b = temp
}

// conditionalCopy demonstrates conditional flow between parameters
func conditionalCopy(a *string, b *string, flag bool) {
	if flag {
		*a = *b
	}
}

// chainedCopy demonstrates transitive flow through multiple parameters
func chainedCopy(a *string, b *string, c *string) {
	*b = *c
	*a = *b
}

// Helper functions for transitive closure testing
func helperCopy(dst *string, src *string) {
	*dst = *src
}

func helperSwap(a *string, b *string) {
	swapStrings(a, b)
}

// Transitive closure test functions - these call other functions
// transitiveViaHelper: calls helperCopy, so b flows to a through the helper
func transitiveViaHelper(a *string, b *string) {
	helperCopy(a, b)
}

// transitiveChain: calls copyString then conditionalCopy
func transitiveChain(a *string, b *string, c *string) {
	copyString(b, c) // c flows to b
	copyString(a, b) // b flows to a
}

// transitiveSwapChain: calls helper that calls swapStrings
func transitiveSwapChain(a *string, b *string) {
	helperSwap(a, b)
}

// transitiveReturn: parameter flows through helper to return value
func transitiveReturn(s *string) string {
	var temp string
	helperCopy(&temp, s)
	return temp
}

// globalCache is a package-level global used to check that the naive method still discovers data
// flow mediated by a global variable (rather than silently dropping it).
var globalCache string

// writeGlobal stores s into globalCache.
func writeGlobal(s string) {
	globalCache = s
}

// readGlobal returns the current value of globalCache.
func readGlobal() string {
	return globalCache
}

// globalRoundTrip writes s into a global and immediately reads it back via a different function,
// so the only path from s to the return goes through the global, not through any direct call or
// return edge between writeGlobal and readGlobal.
func globalRoundTrip(s string) string {
	writeGlobal(s)
	return readGlobal()
}

// escapeCache is a package-level global used to check that the naive method correctly flags
// unsoundness when a global write's only read location is not reachable from the entry function
// being summarized (i.e. the flow escapes the call tree that is actually explored).
var escapeCache string

// writeEscapeGlobal stores s into escapeCache.
func writeEscapeGlobal(s string) {
	escapeCache = s
}

// readEscapeGlobal returns the current value of escapeCache. It is deliberately never called by
// globalEscape (directly or transitively), so it is not reachable from globalEscape's own call
// tree.
func readEscapeGlobal() string {
	return escapeCache
}

// globalEscape writes s into a global that is also read by readEscapeGlobal, a function entirely
// unrelated to globalEscape's own call tree (readEscapeGlobal is only called from main). The naive
// method cannot follow this read since it isn't reachable from globalEscape, so it must be
// reported as a potential source of unsoundness rather than silently missed.
func globalEscape(s string) string {
	writeEscapeGlobal(s)
	return "no flow back to this return through the global"
}

// closureUnboundedDefers demonstrates that recordUnsoundness is invoked for a closure that is only
// entered via free/bound-variable capture (BoundVarNode / a CallNode in ClosureTracing mode), not
// via a regular CallNodeArg. The closure f has its own unbounded defer stack (a defer inside a
// loop), distinct from closureUnboundedDefers' own body, so this can only be caught if the closure
// itself is checked.
func closureUnboundedDefers(s string) string {
	f := func() string {
		for i := 0; i < 3; i++ {
			defer func() {}()
		}
		return s
	}
	return f()
}

// globalDefersCache is used to check that recordUnsoundness is invoked for a function reached only
// via the global write->read jump (not via any Call node).
var globalDefersCache string

// writeGlobalDefersCache stores s into globalDefersCache.
func writeGlobalDefersCache(s string) {
	globalDefersCache = s
}

// readGlobalUnboundedDefers has its own unbounded defer stack and is only reached via the global
// write->read jump from globalRoundTripUnboundedDefers, never via a regular call.
func readGlobalUnboundedDefers() string {
	for i := 0; i < 3; i++ {
		defer func() {}()
	}
	return globalDefersCache
}

// globalRoundTripUnboundedDefers writes s into a global and reads it back via
// readGlobalUnboundedDefers, which has an unbounded defer stack of its own.
func globalRoundTripUnboundedDefers(s string) string {
	writeGlobalDefersCache(s)
	return readGlobalUnboundedDefers()
}

// plainRecoverCallee calls recover() from within a deferred closure, which is the idiomatic (and
// virtually universal) way recover() is used in Go: `defer func() { recover() }()`. The recover()
// call therefore lives in an anonymous function nested one level inside plainRecoverCallee, not in
// plainRecoverCallee's own instructions, so detecting it requires recursing into AnonFuncs.
func plainRecoverCallee(s string) string {
	defer func() {
		recover()
	}()
	return s
}

// plainRecoverGap calls plainRecoverCallee via a regular call, to check that recover() usage
// nested inside a deferred closure is still detected even in the straightforward case.
func plainRecoverGap(s string) string {
	return plainRecoverCallee(s)
}

// Source and Sink are recognized as a taint source/sink by config.yaml's source-to-sink taint
// spec (method "^Source$" / "^Sink$").
func Source() string {
	return "tainted"
}

func Sink(_ string) {}

// sourceGap calls Source and Sink, taint entry points per config.yaml.
func sourceGap(s string) string {
	Sink(Source())
	return s
}

// nestedClosureNonLocal: inner's free variable x is bound to a value that is itself a free
// variable of outer, not a value local to or a parameter of outer.
func nestedClosureNonLocal(x, y *int) *int {
	outer := func() *int {
		inner := func() *int {
			*x = *x + *y
			return x
		}
		return inner()
	}
	return outer()
}

// greeter and wrapper exercise the naive method against an interface implementation:
// wrapper.Greet only ever returns .msg, never .secret, so a field-insensitive analysis would
// (incorrectly) also report .secret flowing to the return.
type greeter interface {
	Greet() string
}

type wrapper struct {
	msg    string
	secret string
}

func (w wrapper) Greet() string {
	return w.msg
}

func main() {
	fooTop("OI")
	bar("OK")
	globalRoundTrip("g")
	globalEscape("g2")
	readEscapeGlobal()
	closureUnboundedDefers("g3")
	globalRoundTripUnboundedDefers("g4")
	plainRecoverGap("g5")
	sourceGap("g6")
	nestedClosureNonLocal(new(int), new(int))
	zoo(contents{
		a: "a",
		b: "b",
		c: "c",
	})

	// Test parameter-to-parameter flows
	s1, s2, s4 := "hello", "world", "hi"
	copyString(&s1, &s4)
	swapStrings(&s1, &s2)
	conditionalCopy(&s1, &s2, true)
	s3 := "test"
	chainedCopy(&s1, &s2, &s3)

	// Test interprocedural flows
	transitiveViaHelper(&s1, &s2)
	transitiveChain(&s1, &s2, &s3)
	transitiveSwapChain(&s1, &s2)
	transitiveReturn(&s1)
	baz("test")

	// Assigned as a pointer so that the (*wrapper).Greet thunk -- the implementation the interface
	// summary test checks -- is actually reachable. With a value here, Go still generates the
	// pointer-receiver thunk but nothing ever calls it.
	var g greeter = &wrapper{msg: "hi"}
	_ = g.Greet()
}
