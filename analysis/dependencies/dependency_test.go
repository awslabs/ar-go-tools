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

package dependencies

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis"
	"golang.org/x/tools/go/ssa"
)

func TestComputePath(t *testing.T) {
	x := computePath("/Users/exampleUser/repoRoot/src/ARG-GoAnalyzer/repo/samplePackage/packageX/packageY/foo.go",
		"github.com/aws/repo/samplePackage/packageX/packageY")
	if x != "github.com/aws/repo/samplePackage/packageX/packageY/foo.go" {
		t.Errorf("error")
	}
	fmt.Println(x)
}

// if the full package name does not appear, we have a situation where the
// filepath doesn't contain the full repo.
// we need to iterate through progressively removing the initial elements from the package name
// until we find a match.

func TestComputePath2(t *testing.T) {
	x := computePath("/Users/exampleUser/reference/repo/samplePackage/samplePackage/samplePackage.go",
		"github.com/aws/repo/samplePackage/samplePackage")
	if x != "github.com/aws/repo/samplePackage/samplePackage/samplePackage.go" {
		t.Errorf("error")
	}
	fmt.Println(x)
}

func TestSamplePackageWorkerDependencies(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../repo/")
	err := os.Chdir(dir)
	if err != nil {
		// We don't expect the samplePackage to be in the pipeline, so don't fail here
		t.Logf("could not change to samplePackage dir: %s", err)
		return
	}

	files := []string{"samplePackage/samplePackage.go",
		"samplePackage/samplePackage_parser.go",
		"samplePackage/samplePackage_unix.go"}
	lp, err := analysis.LoadProgram(nil, "", ssa.BuilderMode(0), files)
	if err != nil {
		t.Fatalf("error loading packages: %s", err)
	}
	program := lp.Program

	dependencyGraph := DependencyAnalysis(program, false, true, nil, false)

	if dependencyGraph != nil {
		//fmt.Println("Checking cycles in dependency graph")
		if dependencyGraph.Cycles() {
			t.Errorf("found cycles in the dependency graph")
		}
	}
}
