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

package statefulrewrite_test

import (
	"embed"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func testRewriteAndBuild(t *testing.T, dirName string, files []string, newReachable map[string]bool) {
	// load the test in testdata
	lp, err := analysistest.LoadTest(testfsys, dirName, files, analysistest.LoadTestOptions{ApplyRewrite: false}).Value()
	if err != nil {
		t.Fatal(err)
	}
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatal(err)
	}
	// Check that the function names in newReachable are not reachable
	// from the entry point
	for fn := range ptrState.ReachableFunctions() {
		fnName := fn.Name()
		if newReachable[fnName] {
			t.Fatalf("function %s should not be reachable before rewrite", fnName)
		}
	}

	spec0 := statefulrewrite.FindImpl(lp, config.CodeIdentifier{Method: "Start", Package: ""})
	if spec0.IsNone() {
		t.Fatal("no impl found")
	}
	spec := spec0.Value().Compile(lp)

	overlay := statefulrewrite.RewriteCallsToReflectValueCall(lp, spec)
	for fileName, fileContents := range overlay {
		t.Logf("overlay %s", fileName)
		t.Logf("%s", fileContents)
	}
	// reload the test in testdata
	lpPost := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false, ExtraOverlay: overlay})
	ptrStatePost, err := result.Bind(lpPost, ptr.NewState).Value()
	if err != nil {
		t.Fatal(err)
	}
	// Reset rechable functions
	for fn := range ptrStatePost.ReachableFunctions() {
		fnName := fn.Name()
		if newReachable[fnName] {
			newReachable[fnName] = false
		}
	}
	// Check that the function names in newReachable are reachable
	// from the entry point
	for fnName, reset := range newReachable {
		if reset {
			t.Fatalf("function %s should be reachable after rewrite", fnName)
		} else {
			t.Logf("good, %s is reachable", fnName)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRewriter(t *testing.T) {
	dirName := filepath.Join("./testdata/simple")
	testRewriteAndBuild(t, dirName, []string{}, map[string]bool{"A": true, "B": true, "C": true})
}

func TestRewriterMultiPkg(t *testing.T) {
	dirName := filepath.Join("./testdata/multipkg")
	testRewriteAndBuild(t, dirName, []string{}, map[string]bool{"A": true, "B": true, "C": true})
}
