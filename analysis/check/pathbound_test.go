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
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

func p(s string) path { return newPath(s, maxPathLen) }

// posS is the position the bounds under test are recorded at.
var posS = newBoundPosition(summaries.ArgumentSNode{Name: "s", Index: 0})

// allPaths are the access paths the law checks quantify over: the position as a whole, two sibling
// fields, and a nested field under each.
var allPaths = []path{p(""), p(".A"), p(".B"), p(".A.X"), p(".B.X")}

// maximal is the field-insensitive bound: every access path truncates to the position itself. It is
// the zero value, which is why a position the summary mentions no field under is read this way.
var maximal lengthBound

// depth1 admits one field under any name; depth2A admits two under .A and one elsewhere.
func depth1() lengthBound  { return boundOfPaths([]path{p(".A")}) }
func depth2A() lengthBound { return boundOfPaths([]path{p(".A.X")}) }

func allBounds() []lengthBound {
	return []lengthBound{maximal, depth1(), depth2A(), boundOfPaths(allPaths)}
}

// TestTruncateLaws checks the properties every consumer of a bound relies on: a truncation subsumes
// the access path it came from, truncating twice is truncating once, and a bounded access path that
// subsumes p also subsumes p's truncation. The last is what makes a must-not-flow depend only on its
// endpoints' truncations.
func TestTruncateLaws(t *testing.T) {
	for _, b := range allBounds() {
		for _, x := range allPaths {
			tx := b.truncate(x)

			if !tx.subsumes(x) {
				t.Errorf("bound %s: truncate(%s) = %s does not subsume it", b, x, tx)
			}
			if got := b.truncate(tx); got != tx {
				t.Errorf("bound %s: truncate not idempotent on %s: %s then %s", b, x, tx, got)
			}
			for _, a := range allPaths {
				if b.truncate(a) != a || !a.subsumes(x) {
					continue
				}
				if !a.subsumes(tx) {
					t.Errorf("bound %s: bounded %s subsumes %s but not its truncation %s", b, a, x, tx)
				}
			}
		}
	}
}

// TestBoundOfPaths checks that the bound a summary induces descends exactly as far as the summary's
// longest mentioned access path, and no further. A summary mentioning no field is read
// field-insensitively, which is the reason an empty summary admits every flow within a position.
func TestBoundOfPaths(t *testing.T) {
	cases := []struct {
		name     string
		mentions []path
		want     map[path]path // access path -> its truncation
	}{
		{
			name:     "no mention is field-insensitive",
			mentions: nil,
			want:     map[path]path{p(""): p(""), p(".A"): p(""), p(".A.X"): p("")},
		},
		{
			name:     "one field mentioned admits one field anywhere",
			mentions: []path{p(".A")},
			want: map[path]path{
				p(""): p(""), p(".A"): p(".A"), p(".B"): p(".B"),
				p(".A.X"): p(".A"), p(".B.X"): p(".B"),
			},
		},
		{
			name:     "a nested mention descends only on that branch",
			mentions: []path{p(".A.X")},
			want: map[path]path{
				p(".A"): p(".A"), p(".A.X"): p(".A.X"),
				p(".B"): p(".B"), p(".B.X"): p(".B"),
			},
		},
		{
			name:     "the deeper of two mentions on one branch wins",
			mentions: []path{p(""), p(".A")},
			want:     map[path]path{p(""): p(""), p(".A"): p(".A"), p(".A.X"): p(".A")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := boundOfPaths(tc.mentions)
			for in, want := range tc.want {
				if got := b.truncate(in); got != want {
					t.Errorf("bound %s: truncate(%s) = %s, want %s", b, in, got, want)
				}
			}
		})
	}
}

// TestImplicitSiblingFields is writeSiblingField: the flow s.A -> s.B is implicit when the position is
// read as a whole and deniable when its fields are distinguished. Both readings are correct, which is
// why a bound has to travel with a summary rather than be recomputed.
func TestImplicitSiblingFields(t *testing.T) {
	insensitive := pathBound{}
	if !insensitive.implicit(posS, p(".A"), p(".B")) {
		t.Error("field-insensitively, s.A -> s.B should be implicit")
	}
	if insensitive.distinguishes(posS, p(".A"), p(".B")) {
		t.Error("field-insensitively, s.A and s.B should not be distinguished")
	}

	sensitive := pathBound{}
	sensitive.record(posS, p(".A"))
	if sensitive.implicit(posS, p(".A"), p(".B")) {
		t.Error("at depth 1, s.A -> s.B should not be implicit")
	}
	if !sensitive.distinguishes(posS, p(".A"), p(".B")) {
		t.Error("at depth 1, s.A and s.B should be distinguished")
	}

	// A flow from an access path to itself stays implicit at every bound: the summary format cannot
	// write it down.
	for _, b := range []pathBound{insensitive, sensitive} {
		for _, x := range allPaths {
			if !b.implicit(posS, x, x) {
				t.Errorf("bound %s: %s -> %s should be implicit", b, x, x)
			}
		}
	}
}

// TestRefines checks the ordering: a finer bound refines a coarser one, and not conversely.
func TestRefines(t *testing.T) {
	if !depth1().refines(maximal) {
		t.Error("depth 1 should refine the maximal bound")
	}
	if maximal.refines(depth1()) {
		t.Error("the maximal bound should not refine depth 1")
	}
	if !depth2A().refines(depth1()) {
		t.Error("depth 2 on .A should refine depth 1")
	}
	if depth1().refines(depth2A()) {
		t.Error("depth 1 should not refine depth 2 on .A")
	}
	for _, b := range allBounds() {
		if !b.refines(b) {
			t.Errorf("bound %s should refine itself", b)
		}
	}
}

// TestJoinIsCoarsestCommonRefinement checks that join refines both operands and preserves every
// distinction either makes. This is what a callee whose call sites enter it at different depths needs:
// taking the shallowest instead would lose a distinction a finer site relied on.
func TestJoinIsCoarsestCommonRefinement(t *testing.T) {
	for _, a := range allBounds() {
		for _, b := range allBounds() {
			j := joinLengthBounds(a, b)
			if !j.refines(a) || !j.refines(b) {
				t.Errorf("join(%s, %s) = %s does not refine both", a, b, j)
			}
			for _, x := range allPaths {
				for _, y := range allPaths {
					if a.truncate(x) != a.truncate(y) && b.truncate(x) != b.truncate(y) {
						continue
					}
					if a.truncate(x) == a.truncate(y) && b.truncate(x) == b.truncate(y) {
						continue
					}
					// One operand tells x and y apart, so the join must too.
					if j.truncate(x) == j.truncate(y) {
						t.Errorf("join(%s, %s) = %s conflates %s and %s", a, b, j, x, y)
					}
				}
			}
		}
	}
}

// TestJoinAcrossCallSites is the reason a callee's bound is a join rather than a minimum. One site
// enters the position as a whole and another enters it at .A. The join keeps .A and .B apart, so a
// summary written against it can still deny the flow the finer site relies on being absent; the
// shallower of the two bounds cannot.
func TestJoinAcrossCallSites(t *testing.T) {
	whole := pathBound{}
	whole.record(posS, p(""))

	field := pathBound{}
	field.record(posS, p(".A"))

	joined := whole.join(field)
	if !joined.distinguishes(posS, p(".A"), p(".B")) {
		t.Errorf("joined bound %s should distinguish s.A from s.B", joined)
	}
	if !joined.refines(whole) || !joined.refines(field) {
		t.Errorf("joined bound %s should refine both call sites' bounds", joined)
	}

	// The shallower of the two loses the distinction, which is the unsound direction.
	if whole.distinguishes(posS, p(".A"), p(".B")) {
		t.Error("the whole-position bound should not distinguish s.A from s.B")
	}
}

// TestBoundOfSummary checks that the bound is read off a summary's mentioned access paths, per
// position.
func TestBoundOfSummary(t *testing.T) {
	arg := summaries.ArgumentSNode{Name: "s", Index: 0}
	ret := summaries.ReturnSNode{Index: 0}
	summ := summaries.DetailedSummary{
		Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
			arg.WithObjectPath(".A"): {ret.WithObjectPath("")},
		},
	}
	v := boundOfSummary(summ)

	argPos := newBoundPosition(arg)
	if !v.distinguishes(argPos, p(".A"), p(".B")) {
		t.Errorf("bound %s: mentioning .A should distinguish the argument's fields", v)
	}
	if got, want := v.truncate(argPos, p(".A.X")), p(".A"); got != want {
		t.Errorf("bound %s: truncate(.A.X) = %s, want %s", v, got, want)
	}

	// The return is mentioned only as a whole, so it stays field-insensitive.
	retPos := newBoundPosition(ret)
	if v.distinguishes(retPos, p(".A"), p(".B")) {
		t.Errorf("bound %s: the return should be read field-insensitively", v)
	}
}

// TestEmptySummaryIsFieldInsensitive is the callee side of the counterexample: a summary declaring
// nothing is read field-insensitively, so it admits a flow between any two fields of a position.
func TestEmptySummaryIsFieldInsensitive(t *testing.T) {
	v := boundOfSummary(summaries.DetailedSummary{
		Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
	})
	if !v.implicit(posS, p(".A"), p(".B")) {
		t.Errorf("bound %s: an empty summary should make s.A -> s.B implicit", v)
	}
}
