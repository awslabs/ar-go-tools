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

package packagescan

import (
	"go/types"
	"io"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// FindImporters searches the list of packages (pkglist) for any imports of the target
// package or packages.
// If exact==true, it will compare the Name() of each imported package to the target.
// This is useful for packages like reflect and unsafe, where you only want exact matches.
// If exact==false, it will see if the Path() of each imported package begins with the
// target.  This is useful for projects spanning multiple projects, such as
// github.com/aws/aws-sdk-go/
func FindImporters(pkglist []*ssa.Package, target string, exact bool, rawfile io.WriteCloser) map[string]bool {
	output := make(map[string]bool, len(pkglist))
	for _, p := range pkglist {
		if target == "" || matchImport(target, exact, p.Pkg.Imports()) {
			output[p.Pkg.Path()] = true
			if rawfile != nil {
				dumpSymbols(p, target, exact, rawfile)
			}
		}
	}
	return output
}

func matchImport(target string, exact bool, imports []*types.Package) bool {
	for _, i := range imports {
		if exact && i.Name() == target || !exact && strings.HasPrefix(i.Path(), target) {
			return true
		}
	}
	return false
}

func dumpSymbols(p *ssa.Package, target string, exact bool, rawfile io.WriteCloser) {
	// placeholder to dump any uses of a symbol to output.  Ignores the fact
	// that we should probably emit the platform... which we don't have here.
	// we might need to go back and create separate rawfiles for each platform
	// or only enable rawfile when used with a single platform.  or ignore it
	// and allow duplicate entries.
}
