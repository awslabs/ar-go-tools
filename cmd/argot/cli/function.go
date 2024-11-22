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
	"fmt"
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// cmdFocus puts a given function into focus by setting state.CurrentFunction
func cmdFocus(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: focus on a specific function.\n", tt.Escape.Blue, cmdFocusName,
			tt.Escape.Reset)
		writeFmt(tt, "\t   Once a function is focused, queries can be made about types, aliasing, etc.\n")
		return false
	}

	funcs := funcsMatchingCommand(tt, c, command)

	if len(funcs) == 0 {
		WriteErr(tt, "No matching function.")
		return false
	}

	if len(funcs) > 1 {
		WriteErr(tt, "Too many matching functions:")
		for _, f := range funcs {
			writeFmt(tt, "%s\n", f.String())
		}
		WriteErr(tt, "Please refine your query.")
		return false
	}

	f := funcs[0]
	if f == nil {
		WriteErr(tt, "Unexpected error: found a matching function, but function is nil.")
		return false
	}

	state.CurrentFunction = f
	WriteSuccess(tt, "Focusing on %s.", f.String())
	tt.SetPrompt(fmt.Sprintf("%s%s >%s ", tt.Escape.Green, f.Name(), tt.Escape.Reset))

	return false
}

// cmdPackage prints information about the package of the current function
func cmdPackage(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		if state.CurrentFunction != nil {
			writeFmt(tt, "\t- %s%s%s: show package of current function.\n", tt.Escape.Blue, cmdPackageName,
				tt.Escape.Reset)
		}
		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "No function is focused.")
		return false
	}

	pkgName := lang.PackageNameFromFunction(state.CurrentFunction)
	writeFmt(tt, "Package %s:\n", pkgName)
	pkg := lang.PackageTypeFromFunction(state.CurrentFunction)
	if pkg == nil {
		WriteErr(tt, "Could not retrieve package object.")
		return false
	}
	writeFmt(tt, "Path: %s\n", pkg.Path())
	writeFmt(tt, "Imports:\n")
	for _, impt := range pkg.Imports() {
		writeFmt(tt, "\t%s\n", impt.Name())
	}
	if _, printScope := command.NamedArgs["scope"]; printScope {
		pkg.Scope().WriteTo(tt, 1, false)
	}
	return false
}

// cmdUnfocus removes the focus on the current function (sets state.CurrentFunction to nil and resets the prompt)
func cmdUnfocus(tt *term.Terminal, c *dataflow.State, _ Command, _ bool) bool {
	if c == nil {
		if state.CurrentFunction != nil {
			writeFmt(tt, "\t- %s%s%s: unfocus current function.\n", tt.Escape.Blue,
				cmdUnfocusName, tt.Escape.Reset)
		}
		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "No function is focused.")
		return false
	}

	WriteSuccess(tt, "Unfocus %s.", state.CurrentFunction.Name())
	state.CurrentFunction = nil
	tt.SetPrompt("> ")

	return false
}

// cmdSsaValue prints the ssa values matching a regex in the state.CurrentFunction
func cmdSsaValue(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		if state.CurrentFunction != nil {
			writeFmt(tt, "\t- %s%s%s: show SSA values matching regex\n", tt.Escape.Blue,
				cmdSsaValueName, tt.Escape.Reset)
		}
		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "You must first focus on a function to show an SSA value.")
		return false
	}

	if len(command.Args) < 1 {
		WriteErr(tt, "You must provide a regex string to filter SSA values.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	for _, param := range state.CurrentFunction.Params {
		if matchValue(r, param) {
			showValue(tt, c, param)
		}
	}

	for _, fv := range state.CurrentFunction.FreeVars {
		if matchValue(r, fv) {
			showValue(tt, c, fv)
		}
	}

	for _, block := range state.CurrentFunction.Blocks {
		for _, instr := range block.Instrs {
			if val, isVal := instr.(ssa.Value); isVal && matchValue(r, val) {
				showValue(tt, c, val)
			}
		}
	}
	return false
}

// cmdSsaInstr prints the ssa instructions matching a regex in the state.CurrentFunction
func cmdSsaInstr(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		if state.CurrentFunction != nil {
			writeFmt(tt, "\t- %s%s%s: show SSA instructions matching regex\n", tt.Escape.Blue,
				cmdSsaInstrName, tt.Escape.Reset)
		}
		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "You must first focus on a function to show an SSA instruction.")
		return false
	}

	if len(command.Args) < 1 {
		WriteErr(tt, "You must provide a regex string to filter SSA instructions.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	for _, block := range state.CurrentFunction.Blocks {
		for _, instr := range block.Instrs {
			if matchInstr(r, instr) {
				showInstr(tt, c, instr)
			}
		}
	}
	return false
}

// cmdMayAlias prints whether matches values may alias according to the pointer analysis
func cmdMayAlias(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		if state.CurrentFunction != nil {
			writeFmt(tt, "\t- %s%s%s: print whether matching values may alias\n", tt.Escape.Blue,
				cmdMayAliasName, tt.Escape.Reset)
		}
		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "You must first focus on a function to query aliasing information.")
		return false
	}

	if len(command.Args) < 1 {
		WriteErr(tt, "You must provide one regex to show aliasing information.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	values1 := map[ssa.Value]bool{}
	lang.IterateValues(state.CurrentFunction, func(_ int, value ssa.Value) {
		if value != nil {
			if r.MatchString(value.Name()) {
				values1[value] = true
			}
		}
	})

	for v1 := range values1 {
		if ptr, ptrExists := c.PointerAnalysis.Queries[v1]; ptrExists {
			writeFmt(tt, "[direct]   %s may alias with:\n", v1.Name())
			lang.IterateValues(state.CurrentFunction, func(_ int, value ssa.Value) {
				if value != nil {
					printAliases(tt, c, value, ptr)
				}
			})
		}
		if ptr, ptrExists := c.PointerAnalysis.IndirectQueries[v1]; ptrExists {
			writeFmt(tt, "[indirect] %s may alias with:\n", v1.Name())
			lang.IterateValues(state.CurrentFunction, func(_ int, value ssa.Value) {
				if value != nil {
					printAliases(tt, c, value, ptr)
				}
			})
		}

	}

	return false
}

func printAliases(tt *term.Terminal, c *dataflow.State, v2 ssa.Value, ptr pointer.Pointer) {
	if ptr2, ptrExists := c.PointerAnalysis.IndirectQueries[v2]; ptrExists && ptr2.MayAlias(ptr) {
		writeFmt(tt, "     [indirect] %s (%s) -> %s\n", v2.Name(), v2, ptr2)
	}

	if ptr2, ptrExists := c.PointerAnalysis.Queries[v2]; ptrExists && ptr2.MayAlias(ptr) {
		writeFmt(tt, "     [direct]   %s (%s) -> %s\n", v2.Name(), v2, ptr2)
	}
}

// cmdWhere prints the position of a function
func cmdWhere(tt *term.Terminal, c *dataflow.State, command Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the location of a function declaration.\n",
			tt.Escape.Blue, cmdWhereName, tt.Escape.Reset)
		return false
	}
	if len(command.Args) < 1 {
		if state.CurrentFunction != nil {
			writeFmt(tt, "Location: %s\n", c.Program.Fset.Position(state.CurrentFunction.Pos()))
		} else {
			WriteErr(tt, "Need at least one function to print position for.")
			cmdWhere(tt, nil, command, withTest)
		}
		return false
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	funcs := findFunc(c, target)
	for _, f := range funcs {
		writeFmt(tt, "Location: %s\n", c.Program.Fset.Position(f.Pos()))
	}
	return false
}

// cmdIntra shows the intermediate result of running the dataflow analysis.
func cmdIntra(tt *term.Terminal, c *dataflow.State, command Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: show the intermediate result of the intraprocedural analysis\n",
			tt.Escape.Blue, cmdIntraName, tt.Escape.Reset)
		writeFmt(tt, "\t    -v    print the intermediate result every time a block is analyzed\n")
		writeFmt(tt, "\t    -h    print this help message\n")
		return false
	}

	if command.Flags["h"] {
		return cmdIntra(tt, nil, command, withTest)
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "You must first focus on a function to run this command!")
		WriteErr(tt, "Example: > focus command-line-arguments.main")
		return false
	}

	var flowInfo *dataflow.FlowInformation

	// This is the function that will be called after each block
	post := func(a *dataflow.IntraAnalysisState) {
		flowInfo = a.FlowInfo()
		if command.Flags["v"] {
			if block := a.Block(); block != nil {
				writeFmt(tt, "\n")
				writeFmt(tt, "---- New block analyzed ----\n")
				showBlock(tt, c, block)
				writeFmt(tt, "     State is ↴\n")
			}
			showFlowInformation(tt, c, flowInfo)
		}
	}

	_, err := dataflow.IntraProceduralAnalysis(c, state.CurrentFunction, true, 0,
		dataflow.IsNodeOfInterest, post)
	if err != nil {
		WriteErr(tt, "Error while analyzing.")
		return false
	}
	if flowInfo != nil {
		state.CurrentDataflowInformation = flowInfo
		if command.Flags["v"] {
			writeFmt(tt, "\n")
			writeFmt(tt, " ⎏  Final state is ↴\n")
		}
		writeFmt(tt, "[function %s%s%s]\n", tt.Escape.Cyan, flowInfo.Function.Name(), tt.Escape.Reset)
		showFlowInformation(tt, c, flowInfo)
	} else {
		WriteErr(tt, "Flow information is nil after analysis. Something went wrong?")
	}
	return false
}

// cmdMark shows intermediate information about a mark in the dataflow analysis
func cmdMark(tt *term.Terminal, c *dataflow.State, command Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: show information about a mark in the intraprocedural analysis\n",
			tt.Escape.Blue, cmdMarkName, tt.Escape.Reset)
		writeFmt(tt, "\t          (only in focused mode)\n")
		writeFmt(tt, "\t    -h    print this help message\n")

		return false
	}

	if state.CurrentFunction == nil {
		WriteErr(tt, "You must first focus on a function to run this command!")
		WriteErr(tt, "Example: > focus command-line-arguments.main")
	}

	if command.Flags["h"] {
		return cmdMark(tt, nil, command, withTest)
	}

	if state.CurrentDataflowInformation == nil || state.CurrentDataflowInformation.Function != state.CurrentFunction {
		writeFmt(tt, "Running the intra-procedural dataflow analysis first...\n")
		_ = cmdIntra(tt, c, command, withTest)
	}

	if state.CurrentDataflowInformation == nil || state.CurrentDataflowInformation.Function != state.CurrentFunction {
		WriteErr(tt, "Reached an unexpected state. Please restart the CLI.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	foundMatch := false
	for mark, instructionSet := range state.CurrentDataflowInformation.LocSet {
		if r.MatchString(mark.String()) {
			foundMatch = true
			writeFmt(tt, "Mark %s\n", mark.String())
			for instr := range instructionSet {
				writeFmt(tt, "\t - %s\n", instr.String())
			}
		}
	}
	if !foundMatch {
		WriteErr(tt, "Did not find any mark matching %s", r.String())
	}

	return false
}

func matchValue(r *regexp.Regexp, val ssa.Value) bool {
	return r.MatchString(val.Name())
}

func matchInstr(r *regexp.Regexp, instr ssa.Instruction) bool {
	return r.MatchString(instr.String())
}

func showValue(tt *term.Terminal, c *dataflow.State, val ssa.Value) {
	writeFmt(tt, "Matching value: %s\n", val.Name())
	writeFmt(tt, "      kind    : %T\n", val)
	writeFmt(tt, "      type    : %s\n", val.Type().String())
	if instr, ok := val.(ssa.Instruction); ok {
		writeFmt(tt, "      instr   : %s\n", instr.String())
	}
	writeFmt(tt, "      location: %s\n", c.Program.Fset.Position(val.Pos()))
	if len(*(val.Referrers())) > 0 {
		writeFmt(tt, "  referrers:\n")
		showReferrers(tt, val)
	}
	if ptset, ok := c.PointerAnalysis.Queries[val]; ok && len(ptset.PointsTo().Labels()) > 0 {
		writeFmt(tt, "  direct aliases:\n")
		showPointer(tt, c.PointerAnalysis.Queries[val])
	}
	if ptset, ok := c.PointerAnalysis.IndirectQueries[val]; ok && len(ptset.PointsTo().Labels()) > 0 {
		writeFmt(tt, "  indirect aliases:\n")
		showPointer(tt, c.PointerAnalysis.IndirectQueries[val])
	}
}

func showReferrers(tt *term.Terminal, val ssa.Value) {
	var entries []displayElement
	referrers := val.Referrers()
	for _, label := range *referrers {
		entries = append(entries, displayElement{
			content: "[" + label.String() + "]",
			escape:  tt.Escape.Blue,
		})
	}
	writeEntries(tt, entries, "    ")
}

func showPointer(tt *term.Terminal, ptr pointer.Pointer) {
	var entries []displayElement
	for _, label := range ptr.PointsTo().Labels() {
		if label.Value() != nil && label.Value().Parent() != nil {
			f := ""
			if label.Value().Parent() != state.CurrentFunction {
				f = fmt.Sprintf(" in %s", label.Value().Parent().Name())
			}
			var dElt displayElement
			if label.Path() != "" {
				dElt = displayElement{
					content: "[" + label.Value().Name() + " @" + label.Path() + " (" + label.Value().String() + f + ")]",
					escape:  tt.Escape.Yellow}
			} else {
				dElt = displayElement{content: "[" + label.Value().Name() + " (" + label.Value().String() + f + ")]",
					escape: tt.Escape.Yellow}
			}
			entries = append(entries, dElt)
		} else {
			entries = append(entries,
				displayElement{content: "[" + label.String() + "]", escape: tt.Escape.White})
		}
	}
	writeEntries(tt, entries, "    ")
}

func showInstr(tt *term.Terminal, c *dataflow.State, instr ssa.Instruction) {
	writeFmt(tt, "Matching instruction: %s\n", instr.String())
	writeFmt(tt, "            location: %s\n", c.Program.Fset.Position(instr.Pos()))
}

func setStr(a ssa.Value, s *string) {
	// Fencing off the insane error with some String() calls on ssa values
	defer func() {
		if r := recover(); r != nil {
			*s = ""
		}
	}()
	*s = a.String()
}

func setName(a ssa.Value, s *string) {
	// Fencing off the insane error with some String() calls on ssa values
	defer func() {
		if r := recover(); r != nil {
			*s = ""
		}
	}()
	*s = a.Name()
}

func showFlowInformation(tt *term.Terminal, c *dataflow.State, fi *dataflow.FlowInformation) {
	if fi.Function == nil {
		return
	}

	lang.IterateInstructions(fi.Function, func(_ int, i ssa.Instruction) {
		writeFmt(tt, "• instruction %s%s%s @ %s:\n", tt.Escape.Blue, i, tt.Escape.Reset,
			c.Program.Fset.Position(i.Pos()))
		// sort and print value -> marks
		var mVals []ssa.Value
		iID := fi.InstrID[i]
		index := iID * fi.NumValues
		for _, val := range fi.MarkedValues[index : index+fi.NumValues] {
			if val != nil {
				mVals = append(mVals, val.GetValue())
			}
		}
		slices.SortFunc(mVals, func(a, b ssa.Value) int {
			var s1, s2 string
			setStr(a, &s1)
			setStr(a, &s2)
			return strings.Compare(s1, s2)
		})
		for _, val := range mVals {
			marks := fi.MarkedValues[index+fi.ValueID[val]]
			var x, vStr, vName string
			setStr(val, &vStr)
			setName(val, &vName)
			_, isFunc := val.(*ssa.Function)
			if isFunc {
				x = "fun " + vName
			} else if vStr != vName {
				x = vName + "=" + vStr
			}
			for path, markSet := range marks.PathMappings() {
				var markStrings []string
				for mark := range markSet {
					markStrings = append(markStrings, formatutil.Red(mark.String()))
				}
				writeFmt(tt, "   %s%-30s%s %s%-10s%s marked by ", tt.Escape.Magenta, x, tt.Escape.Reset,
					tt.Escape.Cyan, path, tt.Escape.Reset)
				writeFmt(tt, "%s\n", strings.Join(markStrings, " & "))
			}
		}
	})
}

// showBlock pretty prints the block on the terminal
func showBlock(tt *term.Terminal, _ *dataflow.State, block *ssa.BasicBlock) {
	writeFmt(tt, "block %d:\n", block.Index)
	writeFmt(tt, "%s P:%d S:%d\n", block.Comment, len(block.Preds), len(block.Succs))

	for _, instr := range block.Instrs {
		writeFmt(tt, "\t")
		switch v := instr.(type) {
		case ssa.Value:
			// Left-align the instruction.
			if name := v.Name(); name != "" {
				writeFmt(tt, "%s = ", name)
			}
			writeFmt(tt, instr.String())
		case nil:
			writeFmt(tt, "<deleted>")
		default:
			writeFmt(tt, instr.String())
		}
		writeFmt(tt, "\n")
	}
}
