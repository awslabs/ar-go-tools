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
	"embed"
	"path/filepath"
	"testing"

	. "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	resultMonad "github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func TestRunBoundingAnalysis(t *testing.T) {
	dir := filepath.Join("testdata", "bounding-analysis")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{"helpers.go"},
		analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	state, err := resultMonad.Bind(ptr.NewState(lp), NewState).Value()
	if err != nil {
		t.Errorf("error building state: %q", err)
	}

	// This is a subset of what the analysis should return
	mustCover := map[string]string{
		"new string (lparen),example1": "make closure example1$1 [t0, t1]",
		"new string (rparen),example1": "make closure example1$1 [t0, t1]",
		"new string (lparen),example2": "make closure example2$1 [t0, t1]",
		"new string (rparen),example2": "make closure example2$1 [t0, t1]",
		"new string (pre),example5":    "make closure example5pre$1 [t0]",
		"new string (x),example6":      "make closure example6$1$1 [x]",
		"new string (pre),example10":   "make closure example10pre$1 [t0]",
	}

	boundingMap, err := RunBoundingAnalysis(state)
	if err != nil {
		t.Errorf("error runnning bounding analysis: %s", err)
	}
	for label, bindings := range boundingMap {
		if label != nil {
			f := " "
			if label.Parent() != nil {
				f = " in " + label.Parent().Name() + " "
			}
			t.Logf("Label %s with Value \"%s\"%sis bound by:\n",
				label.String(), label, f)
		} else {
			t.Logf("Label %s is bound by:\n", label.String())
		}
		for binding := range bindings {
			t.Logf("  %s\n", binding)

			// Checking that the expected binding is covered
			if label != nil && label.Parent() != nil {
				key := label.String() + "," + label.Parent().Name()
				if instrName, ok := mustCover[key]; ok {
					if instrName == binding.MakeClosure.String() {
						delete(mustCover, key)
					}
				}
			}
		}
	}
	if len(mustCover) > 0 {
		for key, data := range mustCover {
			t.Errorf("Label %s should be bound by %s", key, data)
		}
	}
}
