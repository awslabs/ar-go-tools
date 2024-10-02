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

package annotations_test

import (
	"embed"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

//go:embed testdata
var testFileSystem embed.FS

func TestLoadAnnotations(t *testing.T) {
	testProgram, err := analysistest.LoadTest(testFileSystem, "./testdata", []string{"main.go"}, true)
	if err != nil {
		t.Errorf("Error loading test program: %s", err)
	}
	testProgram.Prog.Build()
	logger := config.NewLogGroup(testProgram.Config)
	a, err := annotations.LoadAnnotations(logger, testProgram.Prog.AllPackages())
	if err != nil {
		t.Errorf("error loading annotations: %s", err)
	}
	t.Logf("%d functions scanned", len(a.Funcs))
	for ssaFunc, functionAnnotation := range a.Funcs {
		switch ssaFunc.Name() {
		case "superSensitiveFunction":
			if !testHasAnnotation(functionAnnotation.Mains(), annotations.Sink, "_") {
				t.Errorf("superSensitiveFunction should be annotated with @Sink(_)")
			}
		case "sanitizerOfIo":
			if !testHasAnnotation(functionAnnotation.Mains(), annotations.Sanitizer, "io") {
				t.Errorf("sanitizerOfIo should be annotated with @Sanitizer(io)")
			}
		case "bar":
			if !testHasAnnotation(functionAnnotation.Mains(), annotations.Source, "bar") {
				t.Errorf("bar should be annotated with @Source(bar)")
			}
			if !testHasAnnotation(functionAnnotation.Mains(), annotations.Sink, "html") {
				t.Errorf("bar should be annotated with @Sink(html)")
			}
			for param, paramAnnotations := range functionAnnotation.Params() {
				if param.Name() == "x" && !testHasAnnotation(paramAnnotations, annotations.Sink, "io") {
					t.Errorf("parameter x of bar should be annotated with @Sink(io)")
				}
			}
		case "foo":
			if !testHasAnnotation(functionAnnotation.Mains(), annotations.Source, "io") {
				t.Errorf("foo should be annotated with @Source(io)")
			}
		default:
			if len(functionAnnotation.Mains()) > 0 {
				t.Errorf("unexpected annotations on %s", ssaFunc.Name())
			}
		}
	}
}

func testHasAnnotation(l []annotations.Annotation, kind annotations.AnnotationKind, contents ...string) bool {
	return funcutil.Exists(l,
		func(a annotations.Annotation) bool {
			if a.Kind != kind {
				return false
			}
			for i, content := range contents {
				if a.Tags[i] != content {
					return false
				}
			}
			return true
		})
}
