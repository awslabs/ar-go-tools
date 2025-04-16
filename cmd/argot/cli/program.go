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
	"slices"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/term"
	"golang.org/x/tools/go/packages"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the state.
func cmdLoad(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : load new program\n", tt.Escape.Blue, cmdLoadName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "%s expects at least one argument.", cmdLoadName)
		return false
	}
	sess.args = command.Args
	return cmdRebuild(tt, sess, command, withTest)
}

func cmdLoadPackages(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : load packages\n", tt.Escape.Blue, cmdLoadPackagesName, tt.Escape.Reset)
		writeFmt(tt, "\t  Options:\n")
		writeFmt(tt, "\t    -t    load packages with types\n")
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "%s expects at least one argument.", cmdLoadName)
		return false
	}
	config := packages.Config{
		Mode: packages.NeedName | packages.NeedCompiledGoFiles | packages.LoadImports | packages.LoadAllSyntax,
	}
	if command.Flags["t"] {
		config.Mode = config.Mode | packages.NeedTypes
	}

	pkgList, err := packages.Load(&config, command.Args...)
	if err != nil {
		WriteErr(tt, "failed to load packages: %s", err)
		return false
	}
	if len(pkgList) == 0 {
		writeFmt(tt, "%s? no packages loaded%s\n", tt.Escape.Yellow, tt.Escape.Reset)
		return false
	}

	WriteSuccess(tt, "✔ loaded %d packages:", len(pkgList))
	// Print info about the packages that have been loaded
	pkgMap := make(map[string]*packages.Package)
	namespan := 0
	for _, pkg := range pkgList {
		namespan = max(namespan, len(pkg.Name))
		pkgMap[pkg.PkgPath] = pkg
	}
	// Iterate in sorted path order
	paths := maps.Keys(pkgMap)
	slices.Sort(paths)
	for _, path := range paths {
		pkg := pkgMap[path]
		if pkg == nil {
			continue
		}
		if len(pkg.Errors) > 0 {
			writeFmt(tt, "\t%s%s%s: %s%s\n",
				tt.Escape.Red, pkg.Name, tt.Escape.Reset, strings.Repeat(" ", namespan-len(pkg.Name)), path)
			for _, err := range pkg.Errors {
				writeFmt(tt, "\t\t%s%s%s\n", tt.Escape.Red, err, tt.Escape.Reset)
			}
		} else {
			writeFmt(tt, "\t%s%s%s: %s%s\n",
				tt.Escape.Blue, pkg.Name, tt.Escape.Reset, strings.Repeat(" ", namespan-len(pkg.Name)), path)
		}
	}
	sess.pkgs = pkgMap
	return false
}

func cmdLoadWholeProgram(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : laod the arguments as whole program\n", tt.Escape.Blue, cmdLoadWholeProgramName, tt.Escape.Reset)
		return false
	}

	lp := sess.loadProgram()
	if lp.IsErr() {
		WriteErr(tt, "%s", lp)
		return false
	}
	WriteSuccess(tt, "loaded program with path %s", strings.Join(sess.args, ", "))
	return false
}

func cmdRunPointer(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : run the pointer analysis\n", tt.Escape.Blue, cmdRunPointerName, tt.Escape.Reset)
		return false
	}

	ptr := sess.loadPtrAnalysis()
	if ptr.IsErr() {
		WriteErr(tt, "%s", ptr)
		return false
	}
	WriteSuccess(tt, "finished pointer analysis")
	return false
}

func cmdRunDataflow(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : run the dataflow analysis\n", tt.Escape.Blue, cmdRunDataflowName, tt.Escape.Reset)
		return false
	}

	df := sess.loadDataflowAnalysis()
	if df.IsErr() {
		WriteErr(tt, "%s", df)
		return false
	}
	WriteSuccess(tt, "initialized dataflow analysis information")
	return false
}

// cmdRebuild implements the rebuild command. It reloads the current config state and program state.
// The pointer and dataflow state are cleared.
func cmdRebuild(tt *term.Terminal, sess *session, _ Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including analyzer state.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	res := sess.loadConfig()
	if res.IsOk() {
		sess.loadProgram()
	} else {
		WriteErr(tt, "%s", res)
		return false
	}

	sess.currentFunction = nil
	sess.currentDataflowInformation = nil
	sess.initialPackages = nil
	sess.lpState = nil
	sess.dfState = nil
	sess.ptrState = nil
	return false
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(tt *term.Terminal, sess *session, command Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : load the specified config file\n",
			tt.Escape.Blue, cmdReconfigName, tt.Escape.Reset)
		writeFmt(tt, "\t    Example: %s config.yaml\n", cmdReconfigName)
		return false
	}

	sess.configPath = strings.TrimSpace(command.Args[0])
	oldConfig := sess.cfgState
	sess.cfgState = nil
	res := sess.loadConfig()

	if res.IsErr() {
		WriteErr(tt, "%s", res)
		WriteErr(tt, "You should reload the cli.")
		return false
	}
	if sess.cfgState == nil {
		WriteErr(tt, "Resetting to old config.")
		sess.cfgState = oldConfig
		return false
	}

	if len(command.Args) < 1 {
		WriteSuccess(tt, "Reloaded config from disk.")
	} else {
		WriteSuccess(tt, "Loaded new config!")
	}
	return false
}
