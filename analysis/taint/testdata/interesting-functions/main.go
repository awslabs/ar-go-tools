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

// Package main contains small synthetic examples exercising each signal recorded in
// InterestingFunctionSignals (see analysis/taint/interesting_functions.go).
package main

func source() string {
	return "tainted"
}

func sink(_ string) {}

// recursive1/recursive2 exercise IsRecursive via mutual recursion.
func recursive1(s string, n int) string {
	if n <= 0 {
		return s
	}
	return recursive2(s, n-1)
}

func recursive2(s string, n int) string {
	return recursive1(s, n)
}

func testRecursion() {
	sink(recursive1(source(), 2))
}

// forward passes s through unchanged; used so a tainted value can flow through a CallNodeArg
// (recording signals like concurrency) before reaching an actual sink.
func forward(s string) string {
	return s
}

// concurrent launches a goroutine whose argument is tainted but not itself a sink, exercising
// UnsoundnessConcurrency. It also calls sink directly (not via go) so a real taint flow to a sink
// can be checked.
func concurrent(s string) {
	go forward(s)
	sink(forward(s))
}

func testConcurrency() {
	concurrent(source())
}

// Fanout is an interface implemented by 20 concrete types, so a call through Fanout with a
// tainted receiver exceeds the >10-callee interface-fanout threshold and gives timeout tests
// enough deterministic intra-procedural work to exceed a 1ms deadline.
type Fanout interface {
	F(string) string
}

type impl0 struct{}
type impl1 struct{}
type impl2 struct{}
type impl3 struct{}
type impl4 struct{}
type impl5 struct{}
type impl6 struct{}
type impl7 struct{}
type impl8 struct{}
type impl9 struct{}
type impl10 struct{}
type impl11 struct{}
type impl12 struct{}
type impl13 struct{}
type impl14 struct{}
type impl15 struct{}
type impl16 struct{}
type impl17 struct{}
type impl18 struct{}
type impl19 struct{}

func (impl0) F(s string) string  { return s }
func (impl1) F(s string) string  { return s }
func (impl2) F(s string) string  { return s }
func (impl3) F(s string) string  { return s }
func (impl4) F(s string) string  { return s }
func (impl5) F(s string) string  { return s }
func (impl6) F(s string) string  { return s }
func (impl7) F(s string) string  { return s }
func (impl8) F(s string) string  { return s }
func (impl9) F(s string) string  { return s }
func (impl10) F(s string) string { return s }
func (impl11) F(s string) string { return s }
func (impl12) F(s string) string { return s }
func (impl13) F(s string) string { return s }
func (impl14) F(s string) string { return s }
func (impl15) F(s string) string { return s }
func (impl16) F(s string) string { return s }
func (impl17) F(s string) string { return s }
func (impl18) F(s string) string { return s }
func (impl19) F(s string) string { return s }

func callFanout(f Fanout, s string) string {
	return f.F(s)
}

// WideFanout embeds Fanout and adds a second method, so its method set is a strict superset of
// Fanout's: any concrete type implementing WideFanout also implements Fanout, but the reverse
// isn't true. Calling F via WideFanout should not add a separate WideFanout.F entry when Fanout.F
// (the more general interface for this method) was already recorded for the same function.
type WideFanout interface {
	Fanout
	G(string) string
}

func (impl0) G(s string) string  { return s }
func (impl1) G(s string) string  { return s }
func (impl2) G(s string) string  { return s }
func (impl3) G(s string) string  { return s }
func (impl4) G(s string) string  { return s }
func (impl5) G(s string) string  { return s }
func (impl6) G(s string) string  { return s }
func (impl7) G(s string) string  { return s }
func (impl8) G(s string) string  { return s }
func (impl9) G(s string) string  { return s }
func (impl10) G(s string) string { return s }
func (impl11) G(s string) string { return s }
func (impl12) G(s string) string { return s }
func (impl13) G(s string) string { return s }
func (impl14) G(s string) string { return s }
func (impl15) G(s string) string { return s }
func (impl16) G(s string) string { return s }
func (impl17) G(s string) string { return s }
func (impl18) G(s string) string { return s }
func (impl19) G(s string) string { return s }

func callWideFanout(f WideFanout, s string) string {
	return f.F(s)
}

func testInterfaceFanout(which int) {
	impls := []Fanout{impl0{}, impl1{}, impl2{}, impl3{}, impl4{}, impl5{}, impl6{}, impl7{},
		impl8{}, impl9{}, impl10{}, impl11{}, impl12{}, impl13{}, impl14{}, impl15{}, impl16{},
		impl17{}, impl18{}, impl19{}}
	sink(callFanout(impls[which], source()))
}

func testWideInterfaceFanout(which int) {
	impls := []WideFanout{impl0{}, impl1{}, impl2{}, impl3{}, impl4{}, impl5{}, impl6{}, impl7{},
		impl8{}, impl9{}, impl10{}, impl11{}, impl12{}, impl13{}, impl14{}, impl15{}, impl16{},
		impl17{}, impl18{}, impl19{}}
	sink(callWideFanout(impls[which], source()))
}

// DeepEntry is exported and calls into a chain of private helpers. With a small enough
// unsafe-max-depth, the depth limit is hit somewhere inside deepHelper1/2/3 (all private), and
// the max-callstack-depth signal should be attributed to DeepEntry (the nearest exported
// function in the calling context) rather than to any of the private helpers.
func DeepEntry(s string) string {
	return deepHelper1(s)
}

func deepHelper1(s string) string {
	return deepHelper2(s)
}

func deepHelper2(s string) string {
	return deepHelper3(s)
}

func deepHelper3(s string) string {
	return s
}

func testDeepCallChain() {
	sink(DeepEntry(source()))
}

func main() {
	testRecursion()
	testConcurrency()
	testInterfaceFanout(0)
	// Calling testInterfaceFanout again (from a different call site in main) reaches callFanout's
	// interface dispatch via a second calling context; this should not produce a duplicate
	// InterfaceFanout entry for F, since the underlying fanout fact is identical both times.
	testInterfaceFanout(1)
	testWideInterfaceFanout(2)
	testDeepCallChain()
}
