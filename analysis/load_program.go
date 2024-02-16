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

package analysis

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// PkgLoadMode is the default loading mode in the analyses. We load all possible information.
const PkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

// LoadedProgram represents a loaded program.
type LoadedProgram struct {
	// Program is the SSA version of the program.
	Program *ssa.Program
	// Packages is a list of all packages in the program.
	Packages []*packages.Package
	// Directives is a map from the directive's position in the program to the relevant directive comment.
	Directives Directives
}

// LoadProgram loads a program on platform "platform" using the buildmode provided and the args.
// To understand how to specify the args, look at the documentation of packages.Load.
func LoadProgram(config *packages.Config,
	platform string,
	buildmode ssa.BuilderMode,
	args []string) (LoadedProgram, error) {

	fset := token.NewFileSet()
	if config == nil {
		config = &packages.Config{
			Mode:  PkgLoadMode,
			Tests: false,
			Fset:  fset,
		}
	}

	if platform != "" {
		config.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", platform))
	}

	// load, parse and type check the given packages
	initialPackages, err := packages.Load(config, args...)
	if err != nil {
		return LoadedProgram{}, fmt.Errorf("failed to load packages: %v", err)
	}

	if len(initialPackages) == 0 {
		return LoadedProgram{}, fmt.Errorf("no packages")
	}

	if packages.PrintErrors(initialPackages) > 0 {
		return LoadedProgram{}, fmt.Errorf("errors found, exiting")
	}

	// Construct SSA for all the packages we have loaded
	program, ssaPackages := ssautil.AllPackages(initialPackages, buildmode)

	for i, p := range ssaPackages {
		if p == nil {
			return LoadedProgram{}, fmt.Errorf("cannot build SSA for package %s", initialPackages[i])
		}
	}

	// Build SSA for entire program
	program.Build()

	dir := "."
	if len(args) > 0 {
		dir = filepath.Dir(args[0])
	}
	astPkgs, err := lang.AstPackages(dir, program.Fset)
	if err != nil {
		return LoadedProgram{}, fmt.Errorf("failed to get AST packages: %v", err)
	}

	directives := findDirectives(astPkgs, program.Fset)

	return LoadedProgram{Program: program, Packages: nil, Directives: directives}, nil
}

// AllPackages returns the slice of all packages the set of functions provided as argument belong to.
func AllPackages(funcs map[*ssa.Function]bool) []*ssa.Package {
	pkgs := make(map[*ssa.Package]bool)
	for f := range funcs {
		if f.Package() != nil {
			pkgs[f.Package()] = true
		}
	}
	pkglist := make([]*ssa.Package, 0, len(pkgs))
	for p := range pkgs {
		pkglist = append(pkglist, p)
	}
	sort.Slice(pkglist, func(i, j int) bool {
		return pkglist[i].Pkg.Path() < pkglist[j].Pkg.Path()
	})
	return pkglist
}

// Directives represents a map of directive position to directive.
type Directives map[DirectivePos]Directive

// Directive represents an instruction to Argot in the source code being analyzed.
// It is a comment in the form: `//argot:x`, where x is a valid DirectiveKind.
type Directive struct {
	Kind    DirectiveKind
	Comment *ast.Comment
}

// DirectivePos represents the position of a directive within a program.
type DirectivePos struct {
	Filename string
	Line     int
}

// NewDirectivePos creates a DirectivePos from a token.Position.
func NewDirectivePos(pos token.Position) DirectivePos {
	return DirectivePos{
		Filename: pos.Filename,
		Line:     pos.Line,
	}
}

// DirectiveKind represents the kind of directive.
type DirectiveKind string

const (
	// DirectiveIgnore represents a directive for Argot to ignore a particular line.
	DirectiveIgnore DirectiveKind = "ignore"
)

// NewDirective returns the directive for c and true if c is a valid
// directive comment.
func NewDirective(c *ast.Comment) (Directive, bool) {
	_, after, found := strings.Cut(c.Text, "argot:")
	if !found {
		return Directive{}, false
	}

	switch k := DirectiveKind(after); k {
	case DirectiveIgnore:
		return Directive{Kind: k, Comment: c}, true
	default:
		return Directive{}, false
	}
}

// findDirectives returns all the directives in pkgs.
func findDirectives(pkgs map[string]*ast.Package, fset *token.FileSet) Directives {
	res := make(Directives)
	lang.MapComments(pkgs, func(c *ast.Comment) {
		pos := fset.Position(c.Pos())
		if !pos.IsValid() {
			return
		}

		d, ok := NewDirective(c)
		if !ok {
			return
		}

		dpos := NewDirectivePos(pos)
		res[dpos] = d
	})

	return res
}
