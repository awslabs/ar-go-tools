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
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// LoadedTestProgram represents a loaded test program.
type LoadedTestProgram struct {
	Prog   *ssa.Program
	Config *config.Config
	Pkgs   []*packages.Package
}

// ReadFileDirFS represents a filesystem that can read both directories and files.
type ReadFileDirFS interface {
	fs.ReadDirFS
	fs.ReadFileFS
}

// LoadTest loads the program in the directory dir, looking for a main.go and a config.yaml. If additional files
// are specified as extraFiles, the program will be loaded using those files too.
//
// NOTE
// If the Analysis function runs without error but no analysis entrypoints are detected, that may
// mean that the config's code id's package names do not patch the package name of the SSA program.
// Try changing the package name to the test directory name to fix the issue.
func LoadTest(fsys ReadFileDirFS, dir string, extraFiles []string) (LoadedTestProgram, error) {
	var filePaths []string
	if len(extraFiles) == 0 {
		_ = fs.WalkDir(fsys, dir, func(path string, entry fs.DirEntry, _ error) error {
			if entry != nil && !entry.IsDir() && filepath.Ext(path) == ".go" {
				extraFiles = append(extraFiles, entry.Name())
				filePaths = append(filePaths, path)
			}
			return nil
		})
	} else {
		extraFiles = append(extraFiles, "main.go")
		for _, fileName := range extraFiles {
			filePaths = append(filePaths, filepath.Join(dir, fileName))
		}
	}
	overlay := make(map[string][]byte)
	for i, path := range filePaths {
		b, err := fsys.ReadFile(path)
		if err != nil {
			return LoadedTestProgram{}, fmt.Errorf("failed to read file %s: %w", path, err)
		}
		if len(b) == 0 {
			return LoadedTestProgram{}, fmt.Errorf("empty file at path %s", path)
		}

		name := extraFiles[i]
		overlay[name] = b
	}

	mode := packages.NeedImports | packages.NeedSyntax | packages.NeedTypes | packages.NeedDeps | packages.NeedTypesInfo
	pcfg := packages.Config{
		Mode:    mode,
		Overlay: overlay,
	}
	var patterns []string
	for _, fp := range filePaths {
		patterns = append(patterns, fmt.Sprintf("file=%s", fp))
	}
	pkgs, err := packages.Load(&pcfg, patterns...)
	if err != nil {
		return LoadedTestProgram{}, fmt.Errorf("failed to load packages: %w", err)
	}
	program, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.GlobalDebug|ssa.SanityCheckFunctions)

	configFileName := filepath.Join(dir, "config.yaml")
	cf, err := fsys.ReadFile(configFileName)
	if err != nil {
		return LoadedTestProgram{Pkgs: pkgs},
			fmt.Errorf("failed to read config file %v: %v", configFileName, err)
	}
	cfg, err := config.Load(configFileName, cf)
	if err != nil {
		return LoadedTestProgram{Prog: program, Pkgs: pkgs},
			fmt.Errorf("failed to load config file %v: %v", configFileName, err)
	}
	if cfg.EscapeConfigFile != "" {
		escConfigFileName := cfg.RelPath(cfg.EscapeConfigFile)
		ecf, err := fsys.ReadFile(escConfigFileName)
		if err != nil {
			return LoadedTestProgram{}, fmt.Errorf("failed to read escape config file %v: %v", escConfigFileName, err)
		}
		if err := config.LoadEscape(cfg, ecf); err != nil {
			return LoadedTestProgram{}, fmt.Errorf("failed to load escape config file %v: %v", escConfigFileName, err)
		}
	}

	return LoadedTestProgram{Prog: program, Config: cfg, Pkgs: pkgs}, nil
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

// NewLPos constructs an LPos from pos.
func NewLPos(pos token.Position) LPos {
	return LPos{Line: pos.Line, Filename: pos.Filename}
}

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

// AstFiles returns all the ast files in pkgs.
func AstFiles(pkgs []*packages.Package) []*ast.File {
	var res []*ast.File
	for _, pkg := range pkgs {
		files := pkg.Syntax
		for _, file := range files {
			res = append(res, file)
		}
	}

	return res
}

// ExpectedTaintTargetToSources analyzes the files in astFiles
// and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from targets to sources in the form of two maps from:
// - from sink positions to all the source position that reach that sink.
// - from escape positions to the source of data that escapes.
func ExpectedTaintTargetToSources(fset *token.FileSet, astFiles []*ast.File) (TargetToSources, TargetToSources) {
	sink2source := make(TargetToSources)
	escape2source := make(TargetToSources)
	type sourceInfo struct {
		meta string
		pos  token.Position
	}
	sourceIDToSource := map[string]sourceInfo{}

	// Get all the source positions with their identifiers
	mapComments(astFiles, func(c1 *ast.Comment) {
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
	mapComments(astFiles, func(c1 *ast.Comment) {
		sinkPos := fset.Position(c1.Pos())
		// Match a "@Sink(id1, id2, id3)"
		a := SinkRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sinkIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[sinkIdent]; ok {
					relSink := NewLPos(sinkPos)
					// sinks do not have metadata
					sinkAnnotation := AnnotationID{ID: sinkIdent, Meta: "", Pos: relSink}
					if _, ok := sink2source[sinkAnnotation]; !ok {
						sink2source[sinkAnnotation] = make(map[AnnotationID]bool)
					}
					// sinkIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationID{ID: sinkIdent, Meta: sourcePos.meta, Pos: NewLPos(sourcePos.pos)}
					sink2source[sinkAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	// Get all the escape positions
	mapComments(astFiles, func(c1 *ast.Comment) {
		escapePos := fset.Position(c1.Pos())
		// Match a "@Escape(id1, id2, id3)"
		a := EscapeRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				escapeIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[escapeIdent]; ok {
					relEscape := NewLPos(escapePos)
					// escapes do not have metadata
					escapeAnnotation := AnnotationID{ID: escapeIdent, Meta: "", Pos: relEscape}
					if _, ok := escape2source[escapeAnnotation]; !ok {
						escape2source[escapeAnnotation] = make(map[AnnotationID]bool)
					}
					// escapeIdent is the same as sourceIdent in this branch
					sourceAnnotation := AnnotationID{ID: escapeIdent, Meta: sourcePos.meta, Pos: NewLPos(sourcePos.pos)}
					escape2source[escapeAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	return sink2source, escape2source
}

func mapComments(fs []*ast.File, fmap func(*ast.Comment)) {
	for _, f := range fs {
		for _, c := range f.Comments {
			for _, c1 := range c.List {
				fmap(c1)
			}
		}
	}
}
