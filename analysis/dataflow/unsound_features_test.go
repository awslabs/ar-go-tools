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
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

func TestUnsoundFeatures(t *testing.T) {
	dir := filepath.Join("testdata", "unsound-features")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{},
		analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	state, err := result.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Errorf("error building state: %q", err)
	}
	var unsafeChecked, reflectChecked, recoverChecked bool
	for f := range state.ReachableFunctions() {
		if strings.Contains(f.Name(), "usingUnsafe") {

			uf := dataflow.FindUnsoundFeatures(f)
			if len(uf.UnsafeUsages) <= 2 {
				t.Errorf("Did not detect enough usages of unsage in usingUnsafe")
			}
			unsafeChecked = true
		}
		if strings.Contains(f.Name(), "usingReflect") {
			uf := dataflow.FindUnsoundFeatures(f)
			if len(uf.ReflectUsages) <= 2 {
				t.Errorf("Did not detect enough usages of unsage in usingReflect")
			}
			reflectChecked = true
		}
		if strings.Contains(f.Name(), "usingRecover$1") {
			uf := dataflow.FindUnsoundFeatures(f)
			if len(uf.Recovers) <= 0 {
				t.Errorf("Did not detect enough usages of recover in usingRecover")
			}
			recoverChecked = true
		}
	}
	if !(recoverChecked && reflectChecked && unsafeChecked) {
		t.Errorf("Failed to check for recover, reflect and unsafe functions")
	}
}
