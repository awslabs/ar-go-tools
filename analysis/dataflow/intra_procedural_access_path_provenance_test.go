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

package dataflow

import "testing"

func TestInvertPathTransform(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		transform pathTransform
		want      string
		precise   bool
	}{
		{name: "identity", path: ".A", transform: identityTransform(), want: ".A", precise: true},
		{name: "project field", path: ".C", transform: projectTransform(".B"), want: ".B.C", precise: true},
		{name: "project index", path: ".C", transform: projectTransform("[*]"), want: "[*].C", precise: true},
		{name: "inject field", path: ".B.C", transform: injectTransform(".B"), want: ".C", precise: true},
		{name: "inject sibling does not match", path: ".BodyStart", transform: injectTransform(".Body"), precise: false},
		{name: "coarse", path: ".A", transform: coarseTransform(), precise: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, precise := invertPathTransform(test.path, test.transform)
			if got != test.want || precise != test.precise {
				t.Fatalf("invertPathTransform: got (%q, %v), want (%q, %v)",
					got, precise, test.want, test.precise)
			}
		})
	}
}
