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

package maypanic

// An overapproximating analysis for go routines that may generate an unrecovered panic

import (
	"encoding/json"
	"fmt"
	"go/token"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func locationString(program *ssa.Program, f *ssa.Function) string {
	pos := f.Pos()
	position := program.Fset.Position(pos)
	return position.String()
}

func addGoFunction(f *ssa.Function, pos token.Pos, goFunctions map[*ssa.Function][]token.Pos) {
	// already in map?
	if entry, found := goFunctions[f]; found { // yes
		goFunctions[f] = append(entry, pos)
	} else { // no
		goFunctions[f] = append(make([]token.Pos, 0, 1), pos)
	}
}

// finds the functions that are the argument of "go ..."
func findGoFunctions(allFunctions map[*ssa.Function]bool) map[*ssa.Function][]token.Pos {
	result := make(map[*ssa.Function][]token.Pos)

	for f := range allFunctions {
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				switch v := instr.(type) {
				case *ssa.Go:
					// invoke?
					if v.Call.IsInvoke() {
					} else {
						switch value := v.Call.Value.(type) {
						case *ssa.Function:
							addGoFunction(value, v.Pos(), result)

						case *ssa.MakeClosure:
							switch fn := value.Fn.(type) {
							case *ssa.Function:
								addGoFunction(fn, v.Pos(), result)
							}
						}
					}
				}
			}
		}
	}

	return result
}

func findCreators(program *ssa.Program, f *ssa.Function, goFunctions map[*ssa.Function][]token.Pos) []string {

	result := make([]string, 0)

	creators := goFunctions[f]

	for _, pos := range creators {
		position := program.Fset.Position(pos)
		result = append(result, position.String())
	}

	// sort to get a stable output
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})

	return result
}

func doesRecover(f *ssa.Function) bool {
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
				// invoke?
				if v.Call.IsInvoke() {
				} else {
					switch value := v.Call.Value.(type) {
					case *ssa.Function:

					case *ssa.Builtin:
						builtinName := value.Name()
						switch builtinName {
						case "recover":
							// yes, it calls the "recover" builtin
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func findRecoverFunctions(allFunctions map[*ssa.Function]bool) map[*ssa.Function]bool {
	result := make(map[*ssa.Function]bool)

	for f := range allFunctions {
		if doesRecover(f) {
			result[f] = true
		}
	}

	return result
}

func doesDeferRecover(f *ssa.Function, recoverFunctions map[*ssa.Function]bool) bool {
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Defer:
				// invoke?
				if v.Call.IsInvoke() {
				} else {
					switch value := v.Call.Value.(type) {
					case *ssa.Function:
						_, found := recoverFunctions[value]
						if found {
							return true
						}

					case *ssa.MakeClosure:
						switch fn := value.Fn.(type) {
						case *ssa.Function:
							_, found := recoverFunctions[fn]
							if found {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

func findErroredFunctions(goFunctions map[*ssa.Function][]token.Pos, recoverFunctions map[*ssa.Function]bool) map[*ssa.Function]bool {
	result := make(map[*ssa.Function]bool)

	// look for defer + recover
	for f := range goFunctions {
		if !doesDeferRecover(f, recoverFunctions) {
			result[f] = true
		}
	}

	return result
}

var allowList = []string{
	"archive",
	"bufio",
	"builtin",
	"bytes",
	"cmd",
	"compress",
	"container",
	"context",
	"crypto",
	"database",
	"debug",
	"encoding",
	"errors",
	"expvar",
	"flag",
	"fmt",
	"go",
	"golang.org/x",
	"hash",
	"html",
	"image",
	"index",
	"internal",
	"io",
	"log",
	"math",
	"mime",
	"net",
	"os",
	"path",
	"plugin",
	"reflect",
	"regexp",
	"runtime",
	"sort",
	"strconv",
	"strings",
	"sync",
	"syscall",
	"text",
	"time",
	"unicode",
	"unsafe"}

func allowListed(path string) bool {
	for _, p := range allowList {
		if p == path || strings.HasPrefix(path, p+"/") {
			return true
		}
	}

	return false
}

// MayPanicAnalyzer runs a lightweight may panic analysis on the program
func MayPanicAnalyzer(program *ssa.Program, exclude []string, jsonFlag bool) {

	// Get all the functions
	allFunctions := ssautil.AllFunctions(program)

	// find all functions that are the argument of "go ..."
	goFunctions := findGoFunctions(allFunctions)

	// we filter out the ones we consider "out of scope"
	for f := range goFunctions {
		if f.Pkg != nil {
			pkg := f.Pkg.Pkg
			path := pkg.Path()
			if allowListed(path) || analysisutil.IsExcluded(program, f, exclude) {
				delete(goFunctions, f)
			}
		}
	}

	// find all functions that contain "recover"
	recoverFunctions := findRecoverFunctions(allFunctions)

	// check that the "go functions" contain "defer recover function"
	erroredFunctions := findErroredFunctions(goFunctions, recoverFunctions)

	// get the (full) names of all errored functions
	type nameAndFunction struct {
		name string
		f    *ssa.Function
	}

	functionNames := make([]nameAndFunction, 0, len(allFunctions)+1)
	for f := range erroredFunctions {
		functionNames = append(functionNames, nameAndFunction{name: f.RelString(nil), f: f})
	}

	// sort alphabetically by name
	sort.Slice(functionNames, func(i, j int) bool {
		return functionNames[i].name < functionNames[j].name
	})

	if jsonFlag {
		type Location struct {
			Function string
			Filename string
			Line     int
			Column   int
		}

		makeLocation3 := func(program *ssa.Program, function string, pos *token.Pos) Location {
			position := program.Fset.Position(*pos)
			return Location{function, position.Filename, position.Line, position.Column}
		}

		makeLocation := func(program *ssa.Program, f *ssa.Function) Location {
			function := f.RelString(nil)
			pos := f.Pos()
			return makeLocation3(program, function, &pos)
		}

		type Finding struct {
			Description string
			GoRoutine   Location
			Creators    []Location
		}

		result := make([]Finding, 0, len(functionNames))

		for _, function := range functionNames {
			goRoutine := makeLocation(program, function.f)
			creators := make([]Location, 0)

			creatorPos := goFunctions[function.f]

			for _, pos := range creatorPos {
				creators = append(creators, makeLocation3(program, "", &pos))
			}

			result = append(result, Finding{"unrecovered panic", goRoutine, creators})
		}

		buf, _ := json.Marshal(result)
		fmt.Println(string(buf))
	} else {
		if len(erroredFunctions) == 0 {
			fmt.Printf("no unrecovered panics found\n")
		} else {
			for _, function := range functionNames {
				fmt.Printf(formatutil.Red("unrecovered panic")+" in %s\n", formatutil.Sanitize(function.name))
				fmt.Printf("  %s\n", formatutil.Sanitize(function.name))
				fmt.Printf("  %s\n", formatutil.Sanitize(locationString(program, function.f)))
				creators := findCreators(program, function.f, goFunctions)
				for _, creator := range creators {
					fmt.Printf("  created by %q\n", creator)
				}
			}

			fmt.Printf("%s\n", formatutil.Faint(fmt.Sprintf("Found %d unrecovered panics", len(functionNames))))
		}
	}
}
