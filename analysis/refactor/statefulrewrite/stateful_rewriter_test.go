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
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
)

//go:embed testdata
var testfsys embed.FS

func testRewriteAndBuild(t *testing.T, dirName string, files []string) {
	// load the test in testdata
	lp, err := analysistest.LoadTest(testfsys, dirName, files, analysistest.LoadTestOptions{ApplyRewrite: false}).Value()
	if err != nil {
		t.Fatal(err)
	}
	ptrState, err := loadprogram.NewState(&lp.State).Value()
	if err != nil {
		t.Fatal(err)
	}

	tys, ok := statefulrewrite.FindImpl(ptrState, config.CodeIdentifier{Method: "Start", Package: ""})
	if !ok || len(tys) == 0 {
		t.Fatal("no impl found")
	}

	spec := statefulrewrite.ReflectValueCallRewriterSpec{
		ReceiverType: tys[0],
	}
	overlay := statefulrewrite.RewriteCallsToReflectValueCall(ptrState, spec)
	for fileName, fileContents := range overlay {
		t.Logf("overlay %s", fileName)
		t.Logf("%s", fileContents)
	}
	// reload the test in testdata
	_, err = analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false, ExtraOverlay: overlay}).Value()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRewriter(t *testing.T) {
	dirName := filepath.Join("./testdata/simple")
	testRewriteAndBuild(t, dirName, []string{})
}

func TestRewriterMultiPkg(t *testing.T) {
	dirName := filepath.Join("./testdata/multipkg")
	testRewriteAndBuild(t, dirName, []string{})
}
