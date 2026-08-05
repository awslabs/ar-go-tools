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
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

// syntheticRequestSrc mirrors the shape of aws-sdk-go's request.Request that motivates
// relevantPathsOfType: a struct with several unrelated sibling fields (Config, ClientInfo,
// RequestID, ...) alongside one field (HTTPResponse) that is itself a struct with one relevant
// sub-field (Body) among several irrelevant siblings (StatusCode, Header).
const syntheticRequestSrc = `
package synthtest

type Config struct {
	Region     string
	MaxRetries int
}

type ClientInfo struct {
	ServiceName string
}

type HTTPResponseLike struct {
	StatusCode int
	Header     string
	Body       string
}

type Request struct {
	Config       Config
	ClientInfo   ClientInfo
	HTTPResponse *HTTPResponseLike
	Data         interface{}
	Error        error
	RequestID    string
	SafeBody     *OffsetReaderLike
}

type OffsetReaderLike struct {
	Closed bool
	Buf    string
}
`

// loadSyntheticType type-checks syntheticRequestSrc and returns the named type with the given
// name declared in it (e.g. "Request").
func loadSyntheticType(t *testing.T, name string) types.Type {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthtest.go", syntheticRequestSrc, 0)
	if err != nil {
		t.Fatalf("failed to parse synthetic source: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("synthtest", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatalf("failed to type-check synthetic source: %v", err)
	}
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		t.Fatalf("no type named %q in synthetic source", name)
	}
	return obj.Type()
}

// pathsToStrings converts a slice of path to their dotted-string forms, for readable comparison in
// test failure messages. The result is sorted since relevantPathsOfType/leafPathsUpTo do not
// guarantee any particular order.
func pathsToStrings(paths []path) []string {
	res := make([]string, len(paths))
	for i, p := range paths {
		res[i] = p.String()
	}
	sort.Strings(res)
	return res
}

func mustPaths(t *testing.T, strs ...string) []path {
	t.Helper()
	res := make([]path, len(strs))
	for i, s := range strs {
		res[i] = newPath(s, maxPathLen)
	}
	return res
}

func TestPathsOfTypeUnderBound(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")

	tests := []struct {
		name     string
		mentions []path
		want     []string
	}{
		{
			// Mirrors the Unmarshal destination-side enumeration: the mentioned paths are top-level
			// fields (.Data, .Error), each already a leaf at depth 1, so the bound admits one field
			// anywhere and every other top-level field is enumerated as a single path.
			name:     "top-level mentions admit one field anywhere",
			mentions: mustPaths(t, ".Data", ".Error"),
			want:     []string{".Config", ".ClientInfo", ".HTTPResponse", ".Data", ".Error", ".RequestID", ".SafeBody"},
		},
		{
			// Mirrors the Unmarshal source-side enumeration: .HTTPResponse.Body is mentioned, so the
			// bound descends under HTTPResponse to expose Body and its siblings, while every other
			// top-level field stops at depth 1 (e.g. Config's fields are never enumerated).
			name:     "a nested mention descends only on that branch",
			mentions: mustPaths(t, ".HTTPResponse.Body"),
			want: []string{
				".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody",
				".HTTPResponse.StatusCode", ".HTTPResponse.Header", ".HTTPResponse.Body",
			},
		},
		{
			// Two mentions sharing a prefix: the shared branch is descended once, not duplicated,
			// and the remaining sibling under it is still enumerated.
			name:     "two mentions sharing a prefix",
			mentions: mustPaths(t, ".HTTPResponse.Body", ".HTTPResponse.StatusCode"),
			want: []string{
				".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody",
				".HTTPResponse.StatusCode", ".HTTPResponse.Header", ".HTTPResponse.Body",
			},
		},
		{
			// A shallower bound collapses deeper structure: mentioning HTTPResponse as a whole stops
			// the descent at depth 1, so its fields are not enumerated.
			name:     "a shallow mention collapses the branch's interior",
			mentions: mustPaths(t, ".HTTPResponse"),
			want:     []string{".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody", ".HTTPResponse"},
		},
		{
			// A mentioned path that is not a real field of the type (e.g. a stale path). The bound
			// still admits one field anywhere, since the mention has depth 1, so the result is the
			// top-level enumeration.
			name:     "mentioned path not present in the type",
			mentions: mustPaths(t, ".NoSuchField"),
			want:     []string{".Config", ".ClientInfo", ".HTTPResponse", ".Data", ".Error", ".RequestID", ".SafeBody"},
		},
		{
			// No mention at all: the bound is maximal, so the whole type is one enumerated path. A
			// position the summary never names should collapse entirely, not expand to every leaf.
			name:     "no mentions collapse the whole type to one path",
			mentions: nil,
			want:     []string{""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := boundOfPaths(tc.mentions)
			got := pathsOfTypeUnderBound(requestType, b)
			gotStrs := pathsToStrings(got)
			wantStrs := slices.Clone(tc.want)
			sort.Strings(wantStrs)
			if !slices.Equal(gotStrs, wantStrs) {
				t.Errorf("pathsOfTypeUnderBound(Request, %s) from %v:\n got:  %v\n want: %v",
					b, pathsToStrings(tc.mentions), gotStrs, wantStrs)
			}
		})
	}
}

// TestPathsOfTypeUnderBound_PartitionsMemory checks the two properties the enumeration is relied on
// for: no enumerated path subsumes another (so none names memory another also names), and each is its
// own truncation at the bound (so truncation maps into the enumerated set).
func TestPathsOfTypeUnderBound_PartitionsMemory(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")
	for _, mentions := range [][]path{
		nil,
		mustPaths(t, ".Data"),
		mustPaths(t, ".HTTPResponse.Body"),
		mustPaths(t, ".HTTPResponse.Body", ".Data"),
		leafPathsUpTo(requestType, 2),
	} {
		b := boundOfPaths(mentions)
		got := pathsOfTypeUnderBound(requestType, b)
		for i, p := range got {
			if b.truncate(p) != p {
				t.Errorf("bound %s: enumerated %s is not its own truncation (%s)", b, p, b.truncate(p))
			}
			for j, q := range got {
				if i == j {
					continue
				}
				if p.subsumes(q) {
					t.Errorf("bound %s: enumerated %s subsumes enumerated %s", b, p, q)
				}
			}
		}
	}
}

// TestPathsOfTypeUnderBound_AllLeavesMentioned checks that when every leaf of the type is mentioned,
// the enumeration is full leaf enumeration -- a bound built from the leaves never coarsens one of
// them.
func TestPathsOfTypeUnderBound_AllLeavesMentioned(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")
	full := leafPathsUpTo(requestType, 2)

	got := pathsOfTypeUnderBound(requestType, boundOfPaths(full))
	gotStrs := pathsToStrings(got)
	wantStrs := pathsToStrings(full)
	if !slices.Equal(gotStrs, wantStrs) {
		t.Errorf("enumeration under a bound built from every leaf:\n got:  %v\n want: %v",
			gotStrs, wantStrs)
	}
}

// TestPathsOfTypeUnderBound_Maximal checks the maximal bound: whatever the type, a position read as a
// whole is one enumerated path.
func TestPathsOfTypeUnderBound_Maximal(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")
	got := pathsOfTypeUnderBound(requestType, lengthBound{})
	if len(got) != 1 || got[0].len() != 0 {
		t.Errorf("pathsOfTypeUnderBound(Request, maximal) = %v, want a single empty path", got)
	}
}

func TestValidateSummary(t *testing.T) {
	tests := []struct {
		name    string
		summary summaries.DetailedSummary
		wantErr bool
	}{
		{
			name:    "empty summary is valid",
			summary: summaries.DetailedSummary{},
			wantErr: false,
		},
		{
			name: "single genuine flow is valid",
			summary: summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Index: 0}: {summaries.ReturnSNode{Index: 0}},
			}},
			wantErr: false,
		},
		{
			// Reproduces the reported (*.../aws/csm.metric).TruncateFields case: every declared
			// flow is a field flowing to itself, so the whole summary is vacuous once redundant
			// self-flows are (as they always are, see summaryFlows) filtered out.
			name: "only-self-flows summary is invalid",
			summary: summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ReceiverSNode{ObjectPath: ".AWSException"}:        {summaries.ReceiverSNode{ObjectPath: ".AWSException"}},
				summaries.ReceiverSNode{ObjectPath: ".AWSExceptionMessage"}: {summaries.ReceiverSNode{ObjectPath: ".AWSExceptionMessage"}},
				summaries.ReceiverSNode{ObjectPath: ".ClientID"}:            {summaries.ReceiverSNode{ObjectPath: ".ClientID"}},
			}},
			wantErr: true,
		},
		{
			// A self-flow mixed in with a real flow must NOT be rejected here: summaryFlows
			// silently filters individual self-flows out later, it's only an error when nothing
			// real is left.
			name: "single self-flow among real flows is still valid",
			summary: summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ReceiverSNode{ObjectPath: ".Foo"}: {summaries.ReceiverSNode{ObjectPath: ".Foo"}},
				summaries.ArgumentSNode{Index: 0}:           {summaries.ReturnSNode{Index: 0}},
			}},
			wantErr: false,
		},
		{
			name: "distinct fields of the same node are not self-flows",
			summary: summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ReceiverSNode{ObjectPath: ".Params"}: {summaries.ReceiverSNode{ObjectPath: ".Body"}},
			}},
			wantErr: false,
		},
		{
			// Coarse-to-field is NOT a self-flow by this codebase's existing definition (see
			// summaryFlows: it requires the paths to cover each other in both directions, i.e.
			// be equal) -- a flow from the whole receiver to one of its own fields is considered
			// meaningful, not redundant.
			name: "coarse-to-field flow is not a self-flow",
			summary: summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ReceiverSNode{}: {summaries.ReceiverSNode{ObjectPath: ".Foo"}},
			}},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSummary(tc.summary)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSummary() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
