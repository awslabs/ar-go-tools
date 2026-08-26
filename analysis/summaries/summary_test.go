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

package summaries

import (
	"testing"
)

func TestParseSummaryNode(t *testing.T) {
	testCases := []struct {
		rawNode    string
		structNode SummaryNode
	}{
		// receiver nodes
		{"!receiver", ReceiverSNode{}},
		{"(!receiver).barFoo", ReceiverSNode{ObjectPath: ".barFoo"}},
		// return nodes
		{"!ret", ReturnSNode{Index: 0}},
		{"!ret 0", ReturnSNode{Index: 0}},
		{"!ret 1", ReturnSNode{Index: 1}},
		{"(!ret).foo", ReturnSNode{Index: 0, ObjectPath: ".foo"}},
		{"(!ret 0).foo", ReturnSNode{Index: 0, ObjectPath: ".foo"}},
		{"(!ret 1).bar", ReturnSNode{Index: 1, ObjectPath: ".bar"}},
		// argument nodes
		{"!arg 0", ArgumentSNode{Index: 0}},
		{"!arg 1", ArgumentSNode{Index: 1}},
		{"!arg <fancyName>", ArgumentSNode{Name: "fancyName"}},
		{"(!arg 1).foo", ArgumentSNode{Index: 1, ObjectPath: ".foo"}},
		{"(!arg <bar>).foo", ArgumentSNode{Name: "bar", ObjectPath: ".foo"}},
		{"(!arg <bar>).foo.bar[*]", ArgumentSNode{Name: "bar", ObjectPath: ".foo.bar[*]"}},
	}
	for _, tc := range testCases {
		parsed, err := ParseSummaryNode(tc.rawNode)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if parsed != tc.structNode {
			t.Errorf("Expected %v, got %v", tc.structNode, parsed)
		}
		reParsed, err := ParseSummaryNode(parsed.String())
		if err != nil {
			t.Errorf("Unexpected error when serializing and reparsing: %v", err)
		}
		if reParsed != parsed {
			t.Errorf("Expected %v, got %v", tc.structNode, reParsed)
		}
	}
}

func TestParseSummaryNodeFailures(t *testing.T) {
	testCases := []string{
		"!return",
		"!argument 0",
		"!arg nameNotInLRAngle",
		"!arg <9>",      // not a valid parameter name
		"!arg 0.foo",    // not a valid parameter, if an object path must put base in parentheses
		"!receiver bar", // receiver doesn't accept parameters
	}
	for _, tc := range testCases {
		parsed, err := ParseSummaryNode(tc)
		if err == nil {
			t.Errorf("Expected error, but got: %v", parsed)
		}
	}
}

func TestIsMoreGeneralThan(t *testing.T) {
	testCases := []struct {
		name    string
		want    DetailedSummary
		got     DetailedSummary
		general bool
	}{
		{
			name: "exact match is more general",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			general: true,
		},
		{
			name: "coarse destination covers a field-sensitive destination",
			// !receiver -> !ret 0 should cover !receiver -> (!ret 0).Err, since the field is
			// part of the whole return value declared by the coarser flow.
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0, ObjectPath: ".Err"}},
			}},
			general: true,
		},
		{
			name: "coarse source covers a field-sensitive source",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{ObjectPath: ".Err"}: {ReturnSNode{Index: 0}},
			}},
			general: true,
		},
		{
			name: "field-sensitive want does not cover a coarser got",
			// the reverse of the above: a flow declaring only a specific field is not more
			// general than a flow on the whole node.
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0, ObjectPath: ".Err"}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			general: false,
		},
		{
			name: "different base node is never covered",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Index: 0}: {ReturnSNode{Index: 0}},
			}},
			general: false,
		},
		{
			name: "unrelated field is not covered",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0, ObjectPath: ".Err"}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0, ObjectPath: ".Op"}},
			}},
			general: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.want.IsMoreGeneralThan(tc.got); got != tc.general {
				t.Errorf("expected IsMoreGeneralThan = %v, got %v", tc.general, got)
			}
		})
	}
}

func TestUncoveredFlows(t *testing.T) {
	testCases := []struct {
		name string
		want DetailedSummary
		got  DetailedSummary
		// uncovered is the expected count of flows in got not covered by want.
		uncovered int
	}{
		{
			// Regression case: a coarse declared flow (matching a real (*net.OpError).Temporary
			// ground-truth entry) must cover every field-sensitive flow on the same base, so
			// nothing here is genuinely uncovered.
			name: "coarse want covers all field-sensitive got flows on the same base",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ReceiverSNode{}: {
					ReturnSNode{Index: 0, ObjectPath: ".Err"},
					ReturnSNode{Index: 0, ObjectPath: ".Op"},
				},
			}},
			uncovered: 0,
		},
		{
			// A flow between two declared inputs (not into the return) is genuinely uncovered,
			// matching the real fmt.Append self-flow finding. Got uses named argument nodes
			// (as a computed summary always does), Want uses index-only nodes (as the
			// hand-written ground truth does here) -- these must still match on index alone
			// (see the sameBase name/index regression case below), so the only uncovered flow
			// is the genuine arg-to-arg self-flow, not a naming-mismatch artifact.
			name: "flow between two arguments is genuinely uncovered",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Index: 0}: {ReturnSNode{Index: 0}},
				ArgumentSNode{Index: 1}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Name: "a", Index: 1}: {ArgumentSNode{Name: "b", Index: 0}, ReturnSNode{Index: 0}},
				ArgumentSNode{Name: "b", Index: 0}: {ReturnSNode{Index: 0}},
			}},
			uncovered: 1,
		},
		{
			// Regression case: matches the real fmt.Append ground-truth entry exactly,
			// including its "[*]" vector markers (ObjectPath ".[*]"-ish suffix). "[*]" is a
			// cosmetic annotation ("this node is a slice/array, not a scalar") with no extra
			// path semantics, so it must not prevent a coarse want (arg[*] -> ret[*]) from
			// covering a computed summary's matching whole-value flow (no "[*]" at all).
			name: "vector marker on want does not prevent covering a scalar-looking got",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Index: 0, ObjectPath: "[*]"}: {ReturnSNode{Index: 0, ObjectPath: "[*]"}},
				ArgumentSNode{Index: 1, ObjectPath: "[*]"}: {ReturnSNode{Index: 0, ObjectPath: "[*]"}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Name: "a", Index: 1}: {ArgumentSNode{Name: "b", Index: 0}, ReturnSNode{Index: 0}},
				ArgumentSNode{Name: "b", Index: 0}: {ReturnSNode{Index: 0}},
			}},
			uncovered: 1, // only the genuine arg-to-arg self-flow.
		},
		{
			// Regression case: a ground-truth entry written by name only (no index) must still
			// cover a computed summary's matching named+indexed argument node.
			name: "want argument by name only covers got's matching named+indexed argument",
			want: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Name: "b"}: {ReturnSNode{Index: 0}},
			}},
			got: DetailedSummary{Flows: map[SummaryNode][]SummaryNode{
				ArgumentSNode{Name: "b", Index: 0}: {ReturnSNode{Index: 0}},
			}},
			uncovered: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uncovered := tc.want.UncoveredFlows(tc.got)
			if len(uncovered) != tc.uncovered {
				t.Errorf("expected %d uncovered flows, got %d: %v", tc.uncovered, len(uncovered), uncovered)
			}
		})
	}
}

func TestIsRedundantContainmentFlow(t *testing.T) {
	testCases := []struct {
		name string
		from SummaryNode
		to   SummaryNode
		want bool
	}{
		{
			name: "exact self flow",
			from: ReceiverSNode{},
			to:   ReceiverSNode{},
			want: true,
		},
		{
			name: "coarse to field containment",
			from: ReceiverSNode{},
			to:   ReceiverSNode{ObjectPath: ".Body"},
			want: true,
		},
		{
			name: "vector marker is cosmetic",
			from: ArgumentSNode{Index: 0, ObjectPath: "[*]"},
			to:   ArgumentSNode{Name: "items", Index: 0},
			want: true,
		},
		{
			name: "sibling fields are meaningful",
			from: ReceiverSNode{ObjectPath: ".Params"},
			to:   ReceiverSNode{ObjectPath: ".Body"},
			want: false,
		},
		{
			name: "field to parent is meaningful",
			from: ReceiverSNode{ObjectPath: ".Body"},
			to:   ReceiverSNode{},
			want: false,
		},
		{
			name: "segment prefix is not string prefix",
			from: ReceiverSNode{ObjectPath: ".Body"},
			to:   ReceiverSNode{ObjectPath: ".BodyLength"},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRedundantContainmentFlow(tc.from, tc.to); got != tc.want {
				t.Errorf("IsRedundantContainmentFlow(%s, %s) = %v, want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

func TestWithoutRedundantFlows(t *testing.T) {
	receiver := ReceiverSNode{}
	ret := ReturnSNode{Index: 0}
	left := ReceiverSNode{ObjectPath: ".Left"}
	right := ReceiverSNode{ObjectPath: ".Right"}

	normalized := DetailedSummary{
		Flows: map[SummaryNode][]SummaryNode{
			receiver: {
				ret,
				receiver,
				ReceiverSNode{ObjectPath: ".Body"},
			},
			ReceiverSNode{ObjectPath: ".Field"}: {
				ReturnSNode{Index: 0, ObjectPath: ".Value"},
			},
			left: {right, right},
		},
		Mutates: []SummaryNode{ReceiverSNode{ObjectPath: ".State"}},
	}.WithoutRedundantFlows()

	if got := normalized.Flows[receiver]; len(got) != 1 || got[0] != ret {
		t.Errorf("receiver flows = %v, want only %v", got, ret)
	}
	if got := normalized.Flows[left]; len(got) != 1 || got[0] != right {
		t.Errorf("sibling flows = %v, want only %v", got, right)
	}
	if _, ok := normalized.Flows[ReceiverSNode{ObjectPath: ".Field"}]; ok {
		t.Error("covered field refinement survived normalization")
	}
	if len(normalized.Mutates) != 1 || normalized.Mutates[0].String() != "(!receiver).State" {
		t.Errorf("mutates = %v, want preserved mutation", normalized.Mutates)
	}
}
