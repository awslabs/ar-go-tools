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
	"go/token"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// LoadedTestProgram represents a loaded test program.
type LoadedTestProgram struct {
	analysis.LoadedProgram
	Config *config.Config
}

// LoadTest loads the program in the directory dir, looking for a main.go and a config.yaml. If additional files
// are specified as extraFiles, the program will be loaded using those files too.
func LoadTest(t *testing.T, dir string, extraFiles []string) LoadedTestProgram {
	var err error
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(dir, "config.yaml")
	config.SetGlobalConfig(configFile)
	files := []string{filepath.Join(dir, "./main.go")}
	for _, extraFile := range extraFiles {
		files = append(files, filepath.Join(dir, extraFile))
	}

	prog, err := analysis.LoadProgram(nil, "", ssa.InstantiateGenerics|ssa.GlobalDebug, files)
	if err != nil {
		t.Fatalf("error loading packages: %v", err)
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatalf("error loading global config: %v", err)
	}
	return LoadedTestProgram{
		Config: cfg,
		LoadedProgram: analysis.LoadedProgram{
			Program:    prog.Program,
			Packages:   prog.Packages,
			Directives: prog.Directives,
		},
	}
}

// TargetToSources is a mapping from a target annotation (e.g. ex in @Sink(ex, ex2))
// to a source annotation (e.g. ex in @Source(ex, ex2)).
type TargetToSources map[AnnotationID]map[AnnotationID]bool

// HasMetadata returns true if the TargetToSources mapping contains metadata
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

// SourceToTargets is a mapping from a source annotation to a target annotation.
type SourceToTargets map[AnnotationID]map[AnnotationID]bool

// AnnotationID represents an identifier in an annotation.
type AnnotationID struct {
	// ID is the value of an annotation id.
	// e.g. @Source(id)
	//              ^^
	ID string
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

func (id AnnotationID) String() string {
	return fmt.Sprintf("Id %s:%s at %s", id.ID, id.Meta, id.Pos.String())
}

// SourceRegex matches an annotation of the form @Source(id1, id2 meta2, ...)
// where the "argument" is either an identifier (e.g. id) or an identifier with
// associated "metadata" (e.g. id call:example1->call:helper->call:example1$1).
var SourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*(\w|(\w\s+[a-zA-Z0-9$:\->]+\s*))\s*,?)+)\)`)

// SinkRegex matches annotations of the form "@Sink(id1, id2, id3)"
var SinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

// EscapeRegex matches annotations of the form "@Escape(id1, id2, id3)"
var EscapeRegex = regexp.MustCompile(`//.*@Escape\(((?:\s*\w\s*,?)+)\)`)

// ModSourceRegex matches annotations of the form "@ModSource(id1, id2, id3)".
var ModSourceRegex = regexp.MustCompile(`//.*@ModSource\(((?:\s*\w\s*,?)+)\)`)

// ModRegex matches annotations of the form "@Mod(id1, id2, id3)"
var ModRegex = regexp.MustCompile(`//.*@Mod\(((?:\s*\w\s*,?)+)\)`)

// ModAllocRegex matches annotations of the form "@Alloc(id1, id2, id3)"
var ModAllocRegex = regexp.MustCompile(`//.*@Alloc\(((?:\s*\w\s*,?)+)\)`)

// LPos is a line position
type LPos struct {
	// Filename is the file name of the position
	Filename string
	// Line is the line number in the file
	Line int
}

func (p LPos) String() string {
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

// RemoveColumn transforms a token.Position into a LPos by removing the column information
func RemoveColumn(pos token.Position) LPos {
	return LPos{Line: pos.Line, Filename: pos.Filename}
}

// RelPos drops the column of the position and prepends reldir to the filename of the position
func RelPos(pos token.Position, reldir string) LPos {
	return LPos{Line: pos.Line, Filename: path.Join(reldir, pos.Filename)}
}

// GetExpectedTargetToSources analyzes the files in dir and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from targets to sources in the form of two maps from:
// - from sink positions to all the source position that reach that sink.
// - from escape positions to the source of data that escapes.
func GetExpectedTargetToSources(reldir string, dir string) (TargetToSources, TargetToSources) {
	sink2source := make(TargetToSources)
	escape2source := make(TargetToSources)
	type sourceInfo struct {
		meta string
		pos  token.Position
	}
	sourceIDToSource := map[string]sourceInfo{}
	fset := token.NewFileSet() // positions are relative to fset
	d, err := lang.AstPackages(dir, fset)
	if err != nil {
		panic(fmt.Errorf("failed to get AST packages: %v", err))
	}

	// Get all the source positions with their identifiers
	lang.MapComments(d, func(c1 *ast.Comment) {
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
				sourceIDToSource[sourceIdent] = sourceInfo{meta: meta, pos: pos}
			}
		}
	})

	// Get all the sink positions
	lang.MapComments(d, func(c1 *ast.Comment) {
		sinkPos := fset.Position(c1.Pos())
		// Match a "@Sink(id1, id2, id3)"
		a := SinkRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sinkIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[sinkIdent]; ok {
					relSink := RelPos(sinkPos, reldir)
					// sinks do not have metadata
					sinkAnnotation := AnnotationID{ID: sinkIdent, Meta: "", Pos: relSink}
					if _, ok := sink2source[sinkAnnotation]; !ok {
						sink2source[sinkAnnotation] = make(map[AnnotationID]bool)
					}
					// sinkIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationID{ID: sinkIdent, Meta: sourcePos.meta, Pos: RelPos(sourcePos.pos, reldir)}
					sink2source[sinkAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	// Get all the escape positions
	lang.MapComments(d, func(c1 *ast.Comment) {
		escapePos := fset.Position(c1.Pos())
		// Match a "@Escape(id1, id2, id3)"
		a := EscapeRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				escapeIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[escapeIdent]; ok {
					relEscape := RelPos(escapePos, reldir)
					// escapes do not have metadata
					escapeAnnotation := AnnotationID{ID: escapeIdent, Meta: "", Pos: relEscape}
					if _, ok := escape2source[escapeAnnotation]; !ok {
						escape2source[escapeAnnotation] = make(map[AnnotationID]bool)
					}
					// escapeIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationID{ID: escapeIdent, Meta: sourcePos.meta, Pos: RelPos(sourcePos.pos, reldir)}
					escape2source[escapeAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	return sink2source, escape2source
}

// ExpectedMods tracks expected modptr results.
type ExpectedMods struct {
	Writes map[AnnotationID]struct{}
	Allocs map[AnnotationID]struct{}
}

// GetExpectedMods analyzes the files in dir and looks for comments
// @ModSource(id) and @Mod(id) to construct a mapping from modification sources
// to modifications.
func GetExpectedMods(reldir string, dir string) map[AnnotationID]ExpectedMods {
	fset := token.NewFileSet() // positions are relative to fset
	pkgs, err := lang.AstPackages(dir, fset)
	if err != nil {
		panic(fmt.Errorf("failed to get AST packages: %v", err))
	}

	expected := make(map[AnnotationID]ExpectedMods)
	sourceIDToSourcePos := make(map[string]token.Position)

	// Get all the source positions with their identifiers
	lang.MapComments(pkgs, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "@ModSource(id1, id2, id3)"
		a := ModSourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				sourceIDToSourcePos[sourceIdent] = pos
			}
		}
	})

	lang.MapComments(pkgs, func(c1 *ast.Comment) {
		modPos := fset.Position(c1.Pos())
		// Match a "@Mod(id1, id2, id3)"
		a := ModRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				modIdent := strings.TrimSpace(ident)
				sourcePos, ok := sourceIDToSourcePos[modIdent]
				if !ok {
					continue
				}
				sourceId := AnnotationID{ID: modIdent, Meta: "", Pos: RelPos(sourcePos, reldir)}
				if _, ok := expected[sourceId]; !ok {
					expected[sourceId] = ExpectedMods{
						Writes: make(map[AnnotationID]struct{}),
						Allocs: make(map[AnnotationID]struct{}),
					}
				}

				relMod := RelPos(modPos, reldir)
				modId := AnnotationID{ID: modIdent, Meta: "", Pos: relMod}
				expected[sourceId].Writes[modId] = struct{}{}
			}
		}

		// Match a "@Alloc(id1, id2, id3)"
		m := ModAllocRegex.FindStringSubmatch(c1.Text)
		if len(m) > 1 {
			for _, ident := range strings.Split(m[1], ",") {
				allocIdent := strings.TrimSpace(ident)
				sourcePos, ok := sourceIDToSourcePos[allocIdent]
				if !ok {
					continue
				}
				sourceId := AnnotationID{ID: allocIdent, Meta: "", Pos: RelPos(sourcePos, reldir)}
				if _, ok := expected[sourceId]; !ok {
					expected[sourceId] = ExpectedMods{
						Writes: make(map[AnnotationID]struct{}),
						Allocs: make(map[AnnotationID]struct{}),
					}
				}

				relAlloc := RelPos(modPos, reldir)
				allocId := AnnotationID{ID: allocIdent, Meta: "", Pos: relAlloc}
				expected[sourceId].Allocs[allocId] = struct{}{}
			}
		}
	})

	return expected
}
