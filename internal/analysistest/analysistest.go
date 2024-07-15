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

	"github.com/awslabs/ar-go-tools/analysis"
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
	// Note: adding other package modes like ssa.GlobalDebug breaks the escape analysis tests
	program, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.BuildSerially)
	// Look for a yaml config file first
	configFileName := filepath.Join(dir, "config.yaml")
	cfg, err := config.LoadFromFiles(configFileName)
	if err != nil {
		// Look for a json config file if the yaml couldn't be loaded
		configFileNameJson := filepath.Join(dir, "config.json")
		cfgJson, errJson := config.LoadFromFiles(configFileNameJson)
		if errJson != nil {
			return LoadedTestProgram{Pkgs: pkgs},
				fmt.Errorf("failed to read config file %v (%v) and %v (%v)",
					configFileNameJson, errJson,
					configFileName, err)
		}
		cfg = cfgJson
	}
	program.Build()
	return LoadedTestProgram{Prog: program, Config: cfg, Pkgs: pkgs}, nil
}

// LoadTestFromDisk loads the program in the directory dir, looking for a main.go and a config.yaml
// using the OS file system.
// If additional files are specified as extraFiles, the program will be loaded using those files too.
func LoadTestFromDisk(dir string, extraFiles []string) (LoadedTestProgram, error) {
	configFile := filepath.Join(dir, "config.yaml")
	config.SetGlobalConfig(configFile)
	files := []string{filepath.Join(dir, "./main.go")}
	for _, extraFile := range extraFiles {
		files = append(files, filepath.Join(dir, extraFile))
	}
	var patterns []string
	for _, fileName := range files {
		patterns = append(patterns, fmt.Sprintf("file=%s", fileName))
	}
	mode := packages.NeedImports | packages.NeedSyntax | packages.NeedTypes | packages.NeedDeps | packages.NeedTypesInfo
	pcfg := packages.Config{Mode: mode}
	pkgs, err := packages.Load(&pcfg, patterns...)
	if err != nil {
		return LoadedTestProgram{}, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, err := analysis.LoadProgram(nil, "", ssa.InstantiateGenerics, files)
	if err != nil {
		return LoadedTestProgram{Pkgs: pkgs}, fmt.Errorf("error loading packages: %v", err)
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		return LoadedTestProgram{Prog: prog, Pkgs: pkgs}, fmt.Errorf("failed to load global config: %v", err)
	}

	return LoadedTestProgram{
		Prog:   prog,
		Config: cfg,
		Pkgs:   pkgs,
	}, nil
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

// MapComments runs fmap on every comment in fs.
func MapComments(fs []*ast.File, fmap func(*ast.Comment)) {
	for _, f := range fs {
		for _, c := range f.Comments {
			for _, c1 := range c.List {
				fmap(c1)
			}
		}
	}
}
