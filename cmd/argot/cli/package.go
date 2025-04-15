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

package cli

import (
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/term"
	"golang.org/x/tools/go/packages"
)

func cmdShowPackage(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s <name>: print information about package <name> loaded with load-pkg\n", tt.Escape.Blue,
			cmdShowPackageName, tt.Escape.Reset)
		writeFmt(tt, "\t   Options:\n")
		writeFmt(tt, "\t   -f: print files\n")
		writeFmt(tt, "\t   -i: print imports\n")
	}
	if len(command.Args) == 0 {
		WriteErr(tt, "missing package name")
		return false
	}
	pkgName := command.Args[0]
	printfiles := command.Flags["f"]
	printimports := command.Flags["i"]
	// find package
	pkgs := findPkg(sess, pkgName)
	for _, pkg := range pkgs {
		writeFmt(tt, "Name: %s\n", pkg.Name)
		writeFmt(tt, "Path: %s\n", pkg.PkgPath)
		if printfiles {
			writeFmt(tt, "Files:\n\t%s\n", strings.Join(pkg.GoFiles, "\n\t- "))
		}
		if printimports {
			writeFmt(tt, "Imports:\n\t%s\n", strings.Join(maps.Keys(pkg.Imports), "\n\t"))
		}
	}
	return false
}

func findPkg(sess *session, name string) []*packages.Package {
	pkgs := []*packages.Package{}
	for _, pkg := range sess.Pkgs {
		if pkg.Name == name {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}
