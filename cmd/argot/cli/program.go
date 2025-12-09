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
	"golang.org/x/tools/go/packages"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the state.
func cmdLoad(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : load new program\n", o.EscBlue(), CmdLoadName, o.EscReset())
		o.Write("\t  Options:\n")
		o.Write("\t   --target load program from target name (requires config active)\n")
		o.Write("\t            If no argument is provided, reloads the current program.\n")
		return false
	}
	if namedTarget, exists := command.NamedArgs["target"]; exists {
		if namedTarget == "" {
			// Cannot load empty target
			o.WriteErr("%s --target expects a non-empty target.", CmdLoadName)
			return false
		}
		if sess.configPath == "" {
			o.WriteErr("%s --target option requires an active configuration.", CmdLoadName)
			return false
		}
	}
	if len(command.Args) >= 0 {
		// Update the session args only if some arguments are provided
		sess.args = command.Args
	}
	sess.LoadConfig(o, true)
	return cmdRebuild(o, sess, command, withTest)
}

func cmdLoadPackages(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : load packages\n", o.EscBlue(), CmdLoadPackagesName, o.EscReset())
		o.Write("\t  Options:\n")
		o.Write("\t    -t    load packages with types\n")
		return false
	}

	if len(command.Args) == 0 {
		o.WriteErr("%s expects at least one argument.", CmdLoadName)
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
		o.WriteErr("failed to load packages: %s", err)
		return false
	}
	if len(pkgList) == 0 {
		o.Write("%s? no packages loaded%s\n", o.EscYellow(), o.EscReset())
		return false
	}

	o.WriteSuccess("✔ loaded %d packages:", len(pkgList))
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
			o.Write("\t%s%s%s: %s%s\n",
				o.EscRed(), pkg.Name, o.EscReset(), strings.Repeat(" ", namespan-len(pkg.Name)), path)
			for _, err := range pkg.Errors {
				o.Write("\t\t%s%s%s\n", o.EscRed(), err, o.EscReset())
			}
		} else {
			o.Write("\t%s%s%s: %s%s\n",
				o.EscBlue(), pkg.Name, o.EscReset(), strings.Repeat(" ", namespan-len(pkg.Name)), path)
		}
	}
	sess.pkgs = pkgMap
	return false
}

func cmdRunPointer(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : run the pointer analysis\n", o.EscBlue(), CmdRunPointerName, o.EscReset())
		return false
	}

	ptr := sess.loadPtrAnalysis(o)
	if ptr.IsErr() {
		o.WriteErr("%s", ptr)
		return false
	}
	o.WriteSuccess("finished pointer analysis")
	return false
}

func cmdRunDataflow(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : run the dataflow analysis\n", o.EscBlue(), CmdRunDataflowName, o.EscReset())
		return false
	}

	df := sess.loadDataflowAnalysis(o)
	if df.IsErr() {
		o.WriteErr("%s", df)
		return false
	}
	o.WriteSuccess("initialized dataflow analysis information")
	return false
}

// cmdRebuild implements the rebuild command. It reloads the current config state and program state.
// The pointer and dataflow state are cleared.
func cmdRebuild(o Outputter, sess *Session, _ Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : rebuild the program being analyzed, including analyzer state.\n",
			o.EscBlue(), CmdRebuildName, o.EscReset())
		return false
	}
	res := sess.LoadConfig(o, false)
	sess.currentFunction = nil
	if o.tt != nil {
		o.tt.SetPrompt("> ")
	}
	sess.currentDataflowInformation = nil
	sess.initialPackages = nil
	sess.lpState = nil
	sess.dfState = nil
	sess.ptrState = nil
	if res.IsOk() {
		sess.loadProgram(o)
	} else {
		o.WriteErr("%s", res)
		return false
	}
	return false
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : load the specified config file\n",
			o.EscBlue(), CmdReconfigName, o.EscReset())
		o.Write("\t    Example: %s config.yaml\n", CmdReconfigName)
		return false
	}

	if len(command.Args) == 0 {
		o.WriteErr("%s expects at least one argument.", CmdReconfigName)
		return false
	}

	if len(command.Args) > 1 {
		o.WriteErr("%s expects at most one argument.", CmdReconfigName)
		return false
	}

	sess.configPath = strings.TrimSpace(command.Args[0])
	oldConfig := sess.cfgState
	sess.cfgState = nil
	res := sess.LoadConfig(o, true)

	if res.IsErr() {
		o.WriteErr("%s", res)
		o.WriteErr("You should reload the cli.")
		return false
	}
	if sess.cfgState == nil {
		o.WriteErr("Resetting to old config.")
		sess.cfgState = oldConfig
		return false
	}

	if len(command.Args) < 1 {
		o.WriteSuccess("Reloaded config from disk.")
	} else {
		o.WriteSuccess("Loaded new config!")
	}
	return false
}
