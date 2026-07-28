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

import "testing"

func TestPathIsCoveredBy(t *testing.T) {
	tests := []struct {
		name string
		p    string // p.isCoveredBy(x)
		x    string
		want bool
	}{
		{"equal paths", ".Body", ".Body", true},
		{"equal empty paths", "", "", true},
		{"proper nested prefix", ".Body", ".Body.Start", true},
		{"proper nested prefix reversed", ".Body.Start", ".Body", false},
		{"empty is covered by anything", "", ".Body", true},
		{"anything is not covered by empty", ".Body", "", false},
		{
			// Regression: "Body" is a string-prefix of "BodyStart", but they are sibling field
			// names, not one path nested inside the other. isCoveredBy must not treat
			// field-name string overlap as path containment.
			name: "sibling field names sharing a string prefix",
			p:    ".Body",
			x:    ".BodyStart",
			want: false,
		},
		{
			name: "sibling field names sharing a string prefix (reversed)",
			p:    ".BodyStart",
			x:    ".Body",
			want: false,
		},
		{
			name: "sibling nested field names sharing a string prefix",
			p:    ".Params",
			x:    ".ParamsExtra.Body",
			want: false,
		},
		{"multi-segment nested prefix", ".a.b", ".a.b.c", true},
		{
			name: "multi-segment sibling sharing prefix at last segment",
			p:    ".a.b",
			x:    ".a.bc",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPath(tc.p, maxPathLen)
			x := newPath(tc.x, maxPathLen)
			got := p.isCoveredBy(x)
			if got != tc.want {
				t.Errorf("path(%q).isCoveredBy(path(%q)) = %v, want %v", tc.p, tc.x, got, tc.want)
			}
		})
	}
}
