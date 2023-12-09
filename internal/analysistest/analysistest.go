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

// TargetToSources is a mapping from a target annotation (e.g. ex in @Sink(ex, ex2))
// to a source annotation (e.g. ex in @Source(ex, ex2)).
type TargetToSources map[AnnotationId]map[AnnotationId]bool

func (t TargetToSources) HasMetadata() bool {
	for _, sources := range t {
		for source := range sources {
			if source.Meta != "" {
				return true
			}
		}
	}

	return false
}

// AnnotationId represents an identifier in an annotation.
type AnnotationId struct {
	// Id is the value of an annotation id.
	// e.g. @Source(id)
	//              ^^
	Id string
	// Meta is the identifier of the second portion of an annotation id.
	// This represents an annotation id metadata, usually for trace information.
	// e.g. @Source(id call:example1->call:helper)
	//                 ^^^^^^^^^^^^^^^^^^^^^^^^^^
	// Meta can be empty.
	// e.g. @Source(id)
	Meta string
	// Pos is the position of the annotation.
	Pos LPos
}

func (id AnnotationId) String() string {
	return fmt.Sprintf("Id %s:%s at %s", id.Id, id.Meta, id.Pos.String())
}

// SourceRegex matches an annotation of the form @Source(id1, id2 meta2, ...)
// where the "argument" is either an identifier (e.g. id) or an identifier with
// associated "metadata" (e.g. id call:example1->call:helper->call:example1$1).
var SourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*(\w|(\w\s+[a-zA-Z0-9$:\->]+\s*))\s*,?)+)\)`)

// SinkRegex matches annotations of the form "@Sink(id1, id2, id3)"
var SinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

// EscapeRegex matches annotations of the form "@Escape(id1, id2, id3)"
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

// GetExpectedTargetToSources analyzes the files in dir and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from targets to sources in the form of two maps from:
// - from sink positions to all the source position that reach that sink.
// - from escape positions to the source of data that escapes.
func GetExpectedTargetToSources(reldir string, dir string) (TargetToSources, TargetToSources) {
	d := make(map[string]*ast.Package)
	sink2source := make(TargetToSources)
	escape2source := make(TargetToSources)
	type sourceInfo struct {
		meta string
		pos  token.Position
	}
	sourceIdToSource := map[string]sourceInfo{}
	fset := token.NewFileSet() // positions are relative to fset

	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			d0, err := parser.ParseDir(fset, info.Name(), nil, parser.ParseComments)
			funcutil.Merge(d, d0, func(x *ast.Package, _ *ast.Package) *ast.Package { return x })
			return err
		}
		return nil
	}); err != nil {
		fmt.Println(err)
		return nil, nil
	}

	// Get all the source positions with their identifiers
	mapComments(d, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "@Source(id1, id2, id3 meta)"
		a := SourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				split := strings.Split(sourceIdent, " ")
				meta := ""
				// If id has metadata as in @Source(id meta), then sourceIdent is id and meta is "meta"
				if len(split) == 2 {
					sourceIdent = split[0]
					meta = split[1]
				}
				sourceIdToSource[sourceIdent] = sourceInfo{meta: meta, pos: pos}
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
				sinkIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIdToSource[sinkIdent]; ok {
					relSink := RelPos(sinkPos, reldir)
					// sinks do not have metadata
					sinkAnnotation := AnnotationId{Id: sinkIdent, Meta: "", Pos: relSink}
					if _, ok := sink2source[sinkAnnotation]; !ok {
						sink2source[sinkAnnotation] = make(map[AnnotationId]bool)
					}
					// sinkIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationId{Id: sinkIdent, Meta: sourcePos.meta, Pos: RelPos(sourcePos.pos, reldir)}
					sink2source[sinkAnnotation][sourceAnnotation] = true
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
				escapeIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIdToSource[escapeIdent]; ok {
					relEscape := RelPos(escapePos, reldir)
					// escapes do not have metadata
					escapeAnnotation := AnnotationId{Id: escapeIdent, Meta: "", Pos: relEscape}
					if _, ok := escape2source[escapeAnnotation]; !ok {
						escape2source[escapeAnnotation] = make(map[AnnotationId]bool)
					}
					// escapeIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationId{Id: escapeIdent, Meta: sourcePos.meta, Pos: RelPos(sourcePos.pos, reldir)}
					escape2source[escapeAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	return sink2source, escape2source
}
