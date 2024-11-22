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

package dataflow_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// methodTest runs the test.
//
// HACK sometimes the package name is not command-line-arguments so this was manually patched using string substitutions.
// There may be a more elegant way to do this.
func methodTest(t *testing.T, impl map[string]map[*ssa.Function]bool, name string, expect map[string]bool) {
	if _, ok := impl[name]; !ok {
		name = strings.ReplaceAll(name, "command-line-arguments", "github.com/awslabs/ar-go-tools/analysis/dataflow/testdata/callgraph")
	}
	implementsName := impl[name]
	if implementsName == nil {
		t.Fatalf("interface method %s undefined", name)
	} else if len(implementsName) != len(expect) {
		for f := range implementsName {
			t.Logf("Implements: %s", f.String())
		}
		t.Fatalf("method %s has %d implementations, not %d", name, len(implementsName), len(expect))
	} else {
		for f := range implementsName {
			if f == nil {
				t.Fatalf("method %s has a nil implementations", name)
			}
			fs := f.String()
			if !strings.Contains(fs, "command-line-arguments") {
				fs = strings.ReplaceAll(fs, "github.com/awslabs/ar-go-tools/analysis/dataflow/testdata/callgraph", "command-line-arguments")
			}
			if !expect[fs] {
				t.Fatalf("method %s has an unexpected implementation %s", name, f.String())
			}
		}
	}
}
