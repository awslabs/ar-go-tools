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

package analysisutil

import (
	"golang.org/x/tools/go/packages"
)

// VisitPackages calls f recursively on the root package provided, and then all the imports provided f returns
// true for that package. If f returns false, the imports will not be visited.
func VisitPackages(root *packages.Package, f func(p *packages.Package) bool) {
	seen := map[*packages.Package]bool{}
	queue := []*packages.Package{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		if f(cur) {
			for _, importedPkg := range cur.Imports {
				queue = append(queue, importedPkg)
			}
		}
		seen[cur] = true
	}
}
