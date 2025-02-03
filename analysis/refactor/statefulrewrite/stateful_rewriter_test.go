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
	"fmt"
	"go/types"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"github.com/awslabs/ar-go-tools/internal/shims"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata
var testfsys embed.FS

func findImpl(s *ptr.State) ([]types.Type, bool) {
	seen := make(map[types.Type]struct{})
	for f := range s.ReachableFunctions() {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				return
			}
			if call.Common().IsInvoke() {
				return
			}

			// call to server.New should always be static
			callee := call.Common().StaticCallee()
			pkg := lang.PackageNameFromFunction(callee)
			if pkg == "" {
				return
			}
			if callee.Name() != "start" {
				return
			}

			implObj := lang.GetArgs(call)[0]
			implType := implObj.Type()
			if _, ok := seen[implType]; ok {
				return
			}
			if implType.String() == "interface{}" || implType.String() == "any" {
				// no concrete type: find the concrete type of all pointees
				ptr := s.PointerAnalysis.Queries[implObj]
				for _, label := range ptr.PointsTo().Labels() {
					obj := label.Value()
					if mi, ok := obj.(*ssa.MakeInterface); ok {
						fmt.Println(mi.X.Type().String())
						if namedTy, ok := mi.X.Type().(*types.Named); ok {
							seen[namedTy] = struct{}{}
						}
					}
					if obj.Type().String() == "interface{}" || obj.Type().String() == "any" {
						continue
					}

					seen[obj.Type()] = struct{}{}
				}
			} else {
				seen[implType] = struct{}{}
			}
		})
	}

	if len(seen) == 0 {
		return nil, false
	}

	return shims.Keys(seen), true
}

func TestRewriter(t *testing.T) {
	dirName := filepath.Join("./testdata/simple")
	// load the test in testdata
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false}).Value()
	if err != nil {
		t.Fatal(err)
	}
	ptrState, err := result.Bind(loadprogram.NewState(&lp.State), ptr.NewState).Value()
	if err != nil {
		t.Fatal(err)
	}

	tys, ok := findImpl(ptrState)
	if !ok || len(tys) == 0 {
		t.Fatal("no impl found")
	}

	spec := statefulrewrite.ReflectValueCallRewriterSpec{
		ReceiverType: tys[0].(*types.Named),
	}
	overlay := statefulrewrite.RewriteCallsToReflectValueCall(lp.Program, lp.Packages, spec)
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
