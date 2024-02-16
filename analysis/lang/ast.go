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

package lang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// AstPackages returns all the AST packages in dir (map of package name -> package) with comments parsed.
func AstPackages(dir string, fset *token.FileSet) (map[string]*ast.Package, error) {
	astPkgs := make(map[string]*ast.Package)
	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			parsedDir, err := parser.ParseDir(fset, path, nil, parser.ParseComments)
			if err != nil {
				return fmt.Errorf("failed to parse dir %s: %v", path, err)
			}

			funcutil.Merge(astPkgs, parsedDir, func(x *ast.Package, _ *ast.Package) *ast.Package { return x })
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk dir %s: %v", dir, err)
	}

	return astPkgs, nil
}

// MapComments applies fmap to each comment in packages.
func MapComments(packages map[string]*ast.Package, fmap func(*ast.Comment)) {
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
