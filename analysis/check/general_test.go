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

func TestRelevantPathsOfType(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")

	tests := []struct {
		name          string
		relevantPaths []path
		k             int
		want          []string
	}{
		{
			// Mirrors the Unmarshal destination-side enumeration: relevant paths are top-level
			// fields (.Data, .Error), each already a leaf at depth 1, so every other top-level
			// field collapses to its own single path with no need to recurse further.
			name:          "top-level relevant leaves, k matches their depth",
			relevantPaths: mustPaths(t, ".Data", ".Error"),
			k:             1,
			want:          []string{".Config", ".ClientInfo", ".HTTPResponse", ".Data", ".Error", ".RequestID", ".SafeBody"},
		},
		{
			// Mirrors the Unmarshal source-side enumeration: the relevant path is
			// .HTTPResponse.Body (depth 2), so HTTPResponse is on the relevant spine and must be
			// recursed into to expose Body and its siblings, while every other top-level field
			// (not on the spine) collapses to one path each without recursing into their own
			// substructure (e.g. Config's fields are never individually enumerated).
			name:          "nested relevant leaf, siblings under the spine kept, everything else collapsed",
			relevantPaths: mustPaths(t, ".HTTPResponse.Body"),
			k:             2,
			want: []string{
				".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody",
				".HTTPResponse.StatusCode", ".HTTPResponse.Header", ".HTTPResponse.Body",
			},
		},
		{
			// Two relevant paths sharing a prefix (both under HTTPResponse): both must be exposed
			// exactly, their shared spine (HTTPResponse) must be recursed into once (not
			// duplicated), and the remaining sibling (Header) still collapses to one path.
			name:          "two relevant leaves sharing a prefix",
			relevantPaths: mustPaths(t, ".HTTPResponse.Body", ".HTTPResponse.StatusCode"),
			k:             2,
			want: []string{
				".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody",
				".HTTPResponse.StatusCode", ".HTTPResponse.Header", ".HTTPResponse.Body",
			},
		},
		{
			// A relevant path whose own length exceeds k: since k bounds recursion depth overall
			// (mirroring leafPathsUpTo's existing behavior), the walk cannot go deeper than k
			// regardless of relevance, so the relevant path itself gets truncated to k, same as
			// leafPathsUpTo would for a too-small k. This does not currently arise in practice
			// (k is always derived as at least the longest relevant path's own length), but the
			// function should degrade the same way leafPathsUpTo does rather than panic or drop
			// output entirely.
			name:          "k smaller than the relevant path's own depth",
			relevantPaths: mustPaths(t, ".HTTPResponse.Body"),
			k:             1,
			want:          []string{".Config", ".ClientInfo", ".Data", ".Error", ".RequestID", ".SafeBody", ".HTTPResponse"},
		},
		{
			// A relevant path that doesn't actually exist as a real field of the type (e.g. a
			// stale/mismatched path). Every branch diverges from it immediately, so the result is
			// identical to leafPathsUpTo(t, k) with nothing relevant at all: everything collapses
			// to top-level leaves.
			name:          "relevant path not present in the type",
			relevantPaths: mustPaths(t, ".NoSuchField"),
			k:             2,
			want:          []string{".Config", ".ClientInfo", ".HTTPResponse", ".Data", ".Error", ".RequestID", ".SafeBody"},
		},
		{
			// Empty relevantPaths: nothing in the type is relevant, so the whole tree collapses
			// to a single path representing the entire node -- not full leaf enumeration (that
			// would defeat the purpose: a node not mentioned anywhere in the summary being
			// checked should collapse entirely, not expand to every leaf).
			name:          "no relevant paths collapses the whole type to one path",
			relevantPaths: nil,
			k:             2,
			want:          []string{""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := relevantPathsOfType(requestType, tc.k, tc.relevantPaths)
			gotStrs := pathsToStrings(got)
			wantStrs := slices.Clone(tc.want)
			sort.Strings(wantStrs)
			if !slices.Equal(gotStrs, wantStrs) {
				t.Errorf("relevantPathsOfType(Request, %d, %v):\n got:  %v\n want: %v",
					tc.k, pathsToStrings(tc.relevantPaths), gotStrs, wantStrs)
			}
		})
	}
}

// TestRelevantPathsOfType_MatchesLeafPathsUpToWhenAllRelevant checks that when relevantPaths
// includes every leaf of the type (i.e. nothing is irrelevant), the result is identical to full
// leafPathsUpTo enumeration -- collapsing should never discard or coarsen a genuinely relevant
// leaf.
func TestRelevantPathsOfType_MatchesLeafPathsUpToWhenAllRelevant(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")
	k := 2
	full := leafPathsUpTo(requestType, k)

	got := relevantPathsOfType(requestType, k, full)
	gotStrs := pathsToStrings(got)
	wantStrs := pathsToStrings(full)
	if !slices.Equal(gotStrs, wantStrs) {
		t.Errorf("relevantPathsOfType with every leaf marked relevant:\n got:  %v\n want: %v",
			gotStrs, wantStrs)
	}
}

// TestRelevantPathsOfType_ZeroDepth checks the k == 0 base case, mirroring leafPathsUpTo's own
// k == 0 behavior (a single field-insensitive empty path), regardless of relevantPaths.
func TestRelevantPathsOfType_ZeroDepth(t *testing.T) {
	requestType := loadSyntheticType(t, "Request")
	got := relevantPathsOfType(requestType, 0, mustPaths(t, ".Data"))
	if len(got) != 1 || got[0].len() != 0 {
		t.Errorf("relevantPathsOfType(Request, 0, [.Data]) = %v, want a single empty path", got)
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
