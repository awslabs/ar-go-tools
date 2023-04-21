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

package taint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/functional"
	"github.com/awslabs/argot/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

// Match annotations of the form "@Source(id1, id2, id3)"
var SourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*\w\s*,?)+)\)`)
var SinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

type LPos struct {
	Filename string
	Line     int
}

func (p LPos) String() string {
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

func RemoveColumn(pos token.Position) LPos {
	return LPos{Line: pos.Line, Filename: pos.Filename}
}

// RelPos drops the column of the position and prepends reldir to the filename of the position
func RelPos(pos token.Position, reldir string) LPos {
	return LPos{Line: pos.Line, Filename: path.Join(reldir, pos.Filename)}
}

// getExpectedSourceToSink analyzes the files in dir and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from sources to sink in the form of a map from sink positions to all the source position that
// reach that sink.
func getExpectedSourceToSink(reldir string, dir string) map[LPos]map[LPos]bool {
	var err error
	d := make(map[string]*ast.Package)
	source2sink := map[LPos]map[LPos]bool{}
	sourceIds := map[string]token.Position{}
	fset := token.NewFileSet() // positions are relative to fset

	err = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			d0, err := parser.ParseDir(fset, info.Name(), nil, parser.ParseComments)
			functional.Merge(d, d0, func(x *ast.Package, _ *ast.Package) *ast.Package { return x })
			return err
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return nil
	}

	// Get all the source positions with their identifiers
	for _, f := range d {
		for _, f := range f.Files {
			for _, c := range f.Comments {
				for _, c1 := range c.List {
					pos := fset.Position(c1.Pos())
					// Match a "@Source(id1, id2, id3)"
					a := SourceRegex.FindStringSubmatch(c1.Text)
					if len(a) > 1 {
						for _, ident := range strings.Split(a[1], ",") {
							sourceIdent := strings.TrimSpace(ident)
							sourceIds[sourceIdent] = pos
						}
					}
				}
			}
		}
	}

	for _, f := range d {
		for _, f := range f.Files {
			for _, c := range f.Comments {
				for _, c1 := range c.List {
					sinkPos := fset.Position(c1.Pos())
					// Match a "@Sink(id1, id2, id3)"
					a := SinkRegex.FindStringSubmatch(c1.Text)
					if len(a) > 1 {
						for _, ident := range strings.Split(a[1], ",") {
							sourceIdent := strings.TrimSpace(ident)
							if sourcePos, ok := sourceIds[sourceIdent]; ok {
								relSink := RelPos(sinkPos, reldir)
								if _, ok := source2sink[relSink]; !ok {
									source2sink[relSink] = make(map[LPos]bool)
								}
								source2sink[relSink][RelPos(sourcePos, reldir)] = true
							}
						}
					}
				}
			}
		}
	}
	return source2sink
}

func checkExpectedPositions(t *testing.T, p *ssa.Program, flows TaintFlows, expect map[LPos]map[LPos]bool) {
	seen := make(map[LPos]map[LPos]bool)
	for sink, sources := range ReachedSinkPositions(p, flows) {
		for source := range sources {
			posSink := RemoveColumn(sink)
			if _, ok := seen[posSink]; !ok {
				seen[posSink] = map[LPos]bool{}
			}
			posSource := RemoveColumn(source)
			if _, ok := expect[posSink]; ok && expect[posSink][posSource] {
				seen[posSink][posSource] = true
			} else {
				t.Errorf("ERROR in main.go: false positive:\n\t%s\n flows to\n\t%s\n", posSource, posSink)
			}
		}
	}

	for sinkLine, sources := range expect {
		for sourceLine := range sources {
			if !seen[sinkLine][sourceLine] {
				// Remaining entries have not been detected!
				t.Errorf("ERROR in main.go: failed to detect that:\n%s\nflows to\n%s\n", sourceLine, sinkLine)
			}
		}
	}
}

// runTest runs a test instance by building the program from all the files in files plus a file "main.go", relative
// to the directory dirName
func runTest(t *testing.T, dirName string, files []string) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	// The LoadTest function is relative to the testdata/src/taint-tracking-inter folder so we can
	// load an entire module with subpackages
	program, cfg := utils.LoadTest(t, ".", files)

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := getExpectedSourceToSink(dir, ".")
	checkExpectedPositions(t, program, result.TaintFlows, expected)
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
}

func TestAll(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/basic")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	sink2source := getExpectedSourceToSink(dir, ".")
	for sink, sources := range sink2source {
		for source := range sources {
			fmt.Printf("Source %s -> sink %s\n", source, sink)
		}
	}
}
