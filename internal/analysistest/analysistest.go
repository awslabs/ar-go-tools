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

// Package analysistest contains utility functions for testing the analysis tools.
package analysistest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// LoadTest loads the program in the directory dir, looking for a main.go and a config.yaml. If additional files
// are specified as extraFiles, the program will be loaded using those files too.
func LoadTest(t *testing.T, dir string, extraFiles []string) (*ssa.Program, *config.Config) {
	var err error
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(dir, "config.yaml")
	config.SetGlobalConfig(configFile)
	files := []string{filepath.Join(dir, "./main.go")}
	for _, extraFile := range extraFiles {
		files = append(files, filepath.Join(dir, extraFile))
	}

	pkgs, err := analysis.LoadProgram(nil, "", ssa.InstantiateGenerics|ssa.GlobalDebug, files)
	if err != nil {
		t.Fatalf("error loading packages.")
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatalf("error loading global config.")
	}
	return pkgs, cfg
}

// Match annotations of the form "@Source(id1, id2, id3)"

var SourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*\w\s*,?)+)\)`)
var SinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)
var EscapeRegex = regexp.MustCompile(`//.*@Escape\(((?:\s*\w\s*,?)+)\)`)

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

func mapComments(packages map[string]*ast.Package, fmap func(*ast.Comment)) {
	for _, f := range packages {
		for _, f := range f.Files {
			for _, c := range f.Comments {
				for _, c1 := range c.List {
					fmap(c1)
				}
			}
		}
	}
}

// GetExpectSourceToTargets analyzes the files in dir and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from sources to targets in the form of two maps from:
// - from sink positions to all the source position that reach that sink.
// - from escape positions to the source of data that escapes.
func GetExpectSourceToTargets(reldir string, dir string) (map[LPos]map[LPos]bool, map[LPos]map[LPos]bool) {
	var err error
	d := make(map[string]*ast.Package)
	source2sink := map[LPos]map[LPos]bool{}
	source2escape := map[LPos]map[LPos]bool{}
	sourceIds := map[string]token.Position{}
	fset := token.NewFileSet() // positions are relative to fset

	err = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			d0, err := parser.ParseDir(fset, info.Name(), nil, parser.ParseComments)
			funcutil.Merge(d, d0, func(x *ast.Package, _ *ast.Package) *ast.Package { return x })
			return err
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}

	// Get all the source positions with their identifiers
	mapComments(d, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "@Source(id1, id2, id3)"
		a := SourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				sourceIds[sourceIdent] = pos
			}
		}
	})

	// Get all the sink positions
	mapComments(d, func(c1 *ast.Comment) {
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
	})

	// Get all the escape positions
	mapComments(d, func(c1 *ast.Comment) {
		escapePos := fset.Position(c1.Pos())
		// Match a "@Escape(id1, id2, id3)"
		a := EscapeRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIds[sourceIdent]; ok {
					relEscape := RelPos(escapePos, reldir)
					if _, ok := source2escape[relEscape]; !ok {
						source2escape[relEscape] = make(map[LPos]bool)
					}
					source2escape[relEscape][RelPos(sourcePos, reldir)] = true
				}
			}
		}
	})

	return source2sink, source2escape
}
