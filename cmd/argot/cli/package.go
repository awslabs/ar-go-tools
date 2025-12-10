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
	"regexp"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/packages"
)

func cmdShowPackage(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s <name>: print information about package <name> loaded with load-pkg\n", o.EscBlue(),
			CmdShowPackageName, o.EscReset())
		o.Write("\t   Options:\n")
		o.Write("\t   -f: print files\n")
		o.Write("\t   -i: print imports\n")
		o.Write("\t   -r: find packages by regex matching on path instead of name equality")
	}
	if len(command.Args) == 0 {
		o.WriteErr("missing package name")
		return false
	}
	pkgName := command.Args[0]
	printfiles := command.Flags["f"]
	printimports := command.Flags["i"]
	// find package
	var pkgs []*packages.Package
	if command.Flags["r"] {
		pathRegex, err := regexp.Compile(pkgName)
		if err != nil {
			regexErr(o, pkgName, err)
			return false
		}
		pkgs = findPkgByPathRegex(sess, pathRegex)
	} else {
		pkgs = findPkgByName(sess, pkgName)
	}

	for _, pkg := range pkgs {
		o.Write("Name: %s\n", pkg.Name)
		o.Write("Path: %s\n", pkg.PkgPath)
		if printfiles {
			o.Write("Files:\n\t%s\n", strings.Join(pkg.GoFiles, "\n\t- "))
		}
		if printimports {
			o.Write("Imports:\n\t%s\n", strings.Join(maps.Keys(pkg.Imports), "\n\t"))
		}
	}
	return false
}

func findPkgByName(sess *Session, name string) []*packages.Package {
	pkgs := []*packages.Package{}
	for _, pkg := range sess.pkgs {
		if pkg.Name == name {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func findPkgByPathRegex(sess *Session, rx *regexp.Regexp) []*packages.Package {
	pkgs := []*packages.Package{}
	for _, pkg := range sess.pkgs {
		if rx.MatchString(pkg.PkgPath) {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}
