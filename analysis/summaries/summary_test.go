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
