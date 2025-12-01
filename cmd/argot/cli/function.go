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
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/ssa"
)

// cmdFocus puts a given function into focus by setting state.CurrentFunction
func cmdFocus(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: focus on a specific function.\n", o.EscBlue(), CmdFocusName,
			o.EscReset())
		o.Write("\t   Once a function is focused, queries can be made about types, aliasing, etc.\n")
		return false
	}

	funcs, err := sess.funcsMatchingCommand(o, command)
	if err != nil {
		o.WriteErr("Error: %s", err)
		return false
	}

	if len(funcs) == 0 {
		o.WriteErr("No matching function.")
		return false
	}

	if len(funcs) > 1 {
		o.WriteErr("Too many matching functions:")
		for _, f := range funcs {
			o.Write("%s\n", f.String())
		}
		o.WriteErr("Please refine your query.")
		return false
	}

	f := funcs[0]
	if f == nil {
		o.WriteErr("Unexpected error: found a matching function, but function is nil.")
		return false
	}

	sess.currentFunction = f
	o.WriteSuccess("Focusing on %s.", f.String())
	if o.tt != nil {
		o.tt.SetPrompt(fmt.Sprintf("%s%s >%s ", o.EscGreen(), f.Name(), o.EscReset()))
	}

	return false
}

// cmdPackage prints information about the package of the current function
func cmdPackage(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: show package of current function.\n", o.EscBlue(), CmdPackageName,
			o.EscReset())
		return false
	}

	if sess.currentFunction == nil {
		o.WriteErr("No function is focused.")
		return false
	}

	pkgName := lang.PackageNameFromFunction(sess.currentFunction)
	o.Write("Package %s:\n", pkgName)
	pkg := lang.PackageTypeFromFunction(sess.currentFunction)
	if pkg == nil {
		o.WriteErr("Could not retrieve package object.")
		return false
	}
	o.Write("Path: %s\n", pkg.Path())
	o.Write("Imports:\n")
	for _, impt := range pkg.Imports() {
		o.Write("\t%s\n", impt.Name())
	}
	if _, printScope := command.NamedArgs["scope"]; printScope {
		if o.tt != nil {
			pkg.Scope().WriteTo(o.tt, 1, false)
		}
	}
	return false
}

// cmdUnfocus removes the focus on the current function (sets state.CurrentFunction to nil and resets the prompt)
func cmdUnfocus(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: unfocus current function.\n", o.EscBlue(),
			CmdUnfocusName, o.EscReset())
		return false
	}

	if sess.currentFunction == nil {
		o.WriteErr("No function is focused.")
		return false
	}

	o.WriteSuccess("Unfocus %s.", sess.currentFunction.Name())
	sess.currentFunction = nil
	if o.tt != nil {
		o.tt.SetPrompt("> ")
	}

	return false
}

// cmdSsaValue prints the ssa values matching a regex in the state.CurrentFunction
func cmdSsaValue(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: show SSA values matching regex\n", o.EscBlue(),
			CmdSsaValueName, o.EscReset())
		return false
	}

	if sess.currentFunction == nil {
		o.WriteErr("You must first focus on a function to show an SSA value.")
		return false
	}

	if len(command.Args) < 1 {
		o.WriteErr("You must provide a regex string to filter SSA values.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	for _, param := range sess.currentFunction.Params {
		if matchValue(r, param) {
			showValue(o, sess, param)
		}
	}

	for _, fv := range sess.currentFunction.FreeVars {
		if matchValue(r, fv) {
			showValue(o, sess, fv)
		}
	}

	for _, block := range sess.currentFunction.Blocks {
		for _, instr := range block.Instrs {
			if val, isVal := instr.(ssa.Value); isVal && matchValue(r, val) {
				showValue(o, sess, val)
			}
		}
	}
	return false
}

// cmdSsaInstr prints the ssa instructions matching a regex in the state.CurrentFunction
func cmdSsaInstr(o Outputter, c *Session, command Command, _ bool) bool {
	if c == nil {
		o.Write("\t- %s%s%s: show SSA instructions matching regex\n", o.EscBlue(),
			CmdSsaInstrName, o.EscReset())
		return false
	}

	if c.currentFunction == nil {
		o.WriteErr("You must first focus on a function to show an SSA instruction.")
		return false
	}

	if len(command.Args) < 1 {
		o.WriteErr("You must provide a regex string to filter SSA instructions.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	for _, block := range c.currentFunction.Blocks {
		for _, instr := range block.Instrs {
			if matchInstr(r, instr) {
				showInstr(o, c, instr)
			}
		}
	}
	return false
}

// cmdMayAlias prints whether matches values may alias according to the pointer analysis
func cmdMayAlias(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: print whether matching values may alias\n", o.EscBlue(),
			CmdMayAliasName, o.EscReset())
		return false
	}

	ps, err := sess.loadPtrAnalysis(o).Value()
	if err != nil {
		o.WriteErr("Error loading pointer analysis: %s", err)
		return false
	}

	if sess.currentFunction == nil {
		o.WriteErr("You must first focus on a function to query aliasing information.")
		return false
	}

	if len(command.Args) < 1 {
		o.WriteErr("You must provide one regex to show aliasing information.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	values1 := map[ssa.Value]bool{}
	lang.IterateValues(sess.currentFunction, func(_ int, value ssa.Value) {
		if value != nil {
			if r.MatchString(value.Name()) {
				values1[value] = true
			}
		}
	})

	for v1 := range values1 {
		if ptr, ptrExists := ps.PointerAnalysis.Queries[v1]; ptrExists {
			o.Write("[direct]   %s may alias with:\n", v1.Name())
			lang.IterateValues(sess.currentFunction, func(_ int, value ssa.Value) {
				if value != nil {
					printAliases(o, ps, value, ptr)
				}
			})
		}
		if ptr, ptrExists := ps.PointerAnalysis.IndirectQueries[v1]; ptrExists {
			o.Write("[indirect] %s may alias with:\n", v1.Name())
			lang.IterateValues(sess.currentFunction, func(_ int, value ssa.Value) {
				if value != nil {
					printAliases(o, ps, value, ptr)
				}
			})
		}

	}

	return false
}

func printAliases(o Outputter, ps *ptr.State, v2 ssa.Value, ptr pointer.Pointer) {
	if ptr2, ptrExists := ps.PointerAnalysis.IndirectQueries[v2]; ptrExists && ptr2.MayAlias(ptr) {
		o.Write("     [indirect] %s (%s) -> %s\n", v2.Name(), v2, ptr2)
	}

	if ptr2, ptrExists := ps.PointerAnalysis.Queries[v2]; ptrExists && ptr2.MayAlias(ptr) {
		o.Write("     [direct]   %s (%s) -> %s\n", v2.Name(), v2, ptr2)
	}
}

// cmdWhere prints the position of a function
func cmdWhere(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the location of a function declaration.\n",
			o.EscBlue(), CmdWhereName, o.EscReset())
		return false
	}

	// This command requires loading the program
	lp, err := sess.loadProgram(o).Value()
	if err != nil {
		o.WriteErr("Error loading program: %s", err)
		return false
	}

	if len(command.Args) < 1 {
		if sess.currentFunction != nil {
			o.Write("Location: %s\n", lp.Program.Fset.Position(sess.currentFunction.Pos()))
		} else {
			o.WriteErr("Need at least one function to print position for.")
			cmdWhere(o, nil, command, withTest)
		}
		return false
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	funcs, err := sess.findFunc(target)
	if err != nil {
		o.WriteErr("Error: %s", err)
		return false
	}
	for _, f := range funcs {
		o.Write("Location: %s\n", lp.Program.Fset.Position(f.Pos()))
	}
	return false
}

// cmdIntra shows the intermediate result of running the dataflow analysis.
func cmdIntra(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: show the intermediate result of the intraprocedural analysis\n",
			o.EscBlue(), CmdIntraName, o.EscReset())
		o.Write("\t    -v    print the intermediate result every time a block is analyzed\n")
		o.Write("\t    -h    print this help message\n")
		return false
	}

	if command.Flags["h"] {
		return cmdIntra(o, nil, command, withTest)
	}

	if sess.currentFunction == nil {
		o.WriteErr("You must first focus on a function to run this command!")
		o.WriteErr("Example: > focus command-line-arguments.main")
		return false
	}

	// This command requires loading the dataflow state
	dfs, err := sess.loadDataflowAnalysis(o).Value()
	if err != nil {
		o.WriteErr("Error loading dataflow analysis: %s", err)
		return false
	}

	var flowInfo *dataflow.FlowInformation

	// This is the function that will be called after each block
	post := func(a *dataflow.IntraAnalysisState) {
		flowInfo = a.FlowInfo()
		if command.Flags["v"] {
			if block := a.Block(); block != nil {
				o.Write("\n")
				o.Write("---- New block analyzed ----\n")
				showBlock(o, sess, block)
				o.Write("     State is ↴\n")
			}
			showFlowInformation(o, dfs, flowInfo)
		}
	}

	_, err = dataflow.IntraProceduralAnalysis(dfs, sess.currentFunction, true, 0,
		dataflow.IsNodeOfInterest, post)
	if err != nil {
		o.WriteErr("Error while analyzing.")
		return false
	}
	if flowInfo != nil {
		sess.currentDataflowInformation = flowInfo
		if command.Flags["v"] {
			o.Write("\n")
			o.Write(" ⎏  Final state is ↴\n")
		}
		o.Write("[function %s%s%s]\n", o.EscCyan(), flowInfo.Function.Name(), o.EscReset())
		showFlowInformation(o, dfs, flowInfo)
	} else {
		o.WriteErr("Flow information is nil after analysis. Something went wrong?")
	}
	return false
}

// cmdMark shows intermediate information about a mark in the dataflow analysis
func cmdMark(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: show information about a mark in the intraprocedural analysis\n",
			o.EscBlue(), CmdMarkName, o.EscReset())
		o.Write("\t          (only in focused mode)\n")
		o.Write("\t    -h    print this help message\n")

		return false
	}

	if sess.currentFunction == nil {
		o.WriteErr("You must first focus on a function to run this command!")
		o.WriteErr("Example: > focus command-line-arguments.main")
	}

	if command.Flags["h"] {
		return cmdMark(o, nil, command, withTest)
	}

	if sess.currentDataflowInformation == nil || sess.currentDataflowInformation.Function != sess.currentFunction {
		o.Write("Running the intra-procedural dataflow analysis first...\n")
		_ = cmdIntra(o, sess, command, withTest)
	}

	if sess.currentDataflowInformation == nil || sess.currentDataflowInformation.Function != sess.currentFunction {
		o.WriteErr("Reached an unexpected state. Please restart the CLI.")
		return false
	}

	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	foundMatch := false
	for mark, instructionSet := range sess.currentDataflowInformation.LocSet {
		if r.MatchString(mark.String()) {
			foundMatch = true
			o.Write("Mark %s\n", mark.String())
			for instr := range instructionSet {
				o.Write("\t - %s\n", instr.String())
			}
		}
	}
	if !foundMatch {
		o.WriteErr("Did not find any mark matching %s", r.String())
	}

	return false
}

func matchValue(r *regexp.Regexp, val ssa.Value) bool {
	return r.MatchString(val.Name())
}

func matchInstr(r *regexp.Regexp, instr ssa.Instruction) bool {
	return r.MatchString(instr.String())
}

func showValue(o Outputter, sess *Session, val ssa.Value) {
	o.Write("Matching value: %s\n", val.Name())
	o.Write("      kind    : %T\n", val)
	o.Write("      type    : %s\n", val.Type().String())
	if instr, ok := val.(ssa.Instruction); ok {
		o.Write("      instr   : %s\n", instr.String())
	}
	o.Write("      location: %s\n", sess.programOrPanic().Fset.Position(val.Pos()))
	if len(*(val.Referrers())) > 0 {
		o.Write("  referrers:\n")
		showReferrers(sess, o, val)
	}
	if sess.ptrState != nil {
		ps := sess.ptrState
		if ptset, ok := ps.PointerAnalysis.Queries[val]; ok && len(ptset.PointsTo().Labels()) > 0 {
			o.Write("  direct aliases:\n")
			showPointer(o, sess, ps.PointerAnalysis.Queries[val])
		}
		if ptset, ok := ps.PointerAnalysis.IndirectQueries[val]; ok && len(ptset.PointsTo().Labels()) > 0 {
			o.Write("  indirect aliases:\n")
			showPointer(o, sess, ps.PointerAnalysis.IndirectQueries[val])
		}
	}
}

func showReferrers(sess *Session, o Outputter, val ssa.Value) {
	var entries []displayElement
	referrers := val.Referrers()
	for _, label := range *referrers {
		entries = append(entries, displayElement{
			content: "[" + label.String() + "]",
			escape:  o.EscBlue(),
		})
	}
	writeEntries(o, sess, entries, "    ")
}

func showPointer(o Outputter, sess *Session, ptr pointer.Pointer) {
	var entries []displayElement
	for _, label := range ptr.PointsTo().Labels() {
		if label.Value() != nil && label.Value().Parent() != nil {
			f := ""
			if label.Value().Parent() != sess.currentFunction {
				f = fmt.Sprintf(" in %s", label.Value().Parent().Name())
			}
			var dElt displayElement
			if label.Path() != "" {
				dElt = displayElement{
					content: "[" + label.Value().Name() + " @" + label.Path() + " (" + label.Value().String() + f + ")]",
					escape:  o.EscYellow()}
			} else {
				dElt = displayElement{content: "[" + label.Value().Name() + " (" + label.Value().String() + f + ")]",
					escape: o.EscYellow()}
			}
			entries = append(entries, dElt)
		} else {
			entries = append(entries,
				displayElement{content: "[" + label.String() + "]", escape: o.EscWhite()})
		}
	}
	writeEntries(o, sess, entries, "    ")
}

func showInstr(o Outputter, c *Session, instr ssa.Instruction) {
	o.Write("Matching instruction: %s\n", instr.String())
	o.Write("            location: %s\n", c.programOrPanic().Fset.Position(instr.Pos()))
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

func showFlowInformation(o Outputter, c *dataflow.State, fi *dataflow.FlowInformation) {
	if fi.Function == nil {
		return
	}

	lang.IterateInstructions(fi.Function, func(_ int, i ssa.Instruction) {
		o.Write("• instruction %s%s%s @ %s:\n", o.EscBlue(), i, o.EscReset(),
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
				o.Write("   %s%-30s%s %s%-10s%s marked by ", o.EscMagenta(), x, o.EscReset(),
					o.EscCyan(), path, o.EscReset())
				o.Write("%s\n", strings.Join(markStrings, " & "))
			}
		}
	})
}

// showBlock pretty prints the block on the terminal
func showBlock(o Outputter, _ *Session, block *ssa.BasicBlock) {
	o.Write("block %d:\n", block.Index)
	o.Write("%s P:%d S:%d\n", block.Comment, len(block.Preds), len(block.Succs))

	for _, instr := range block.Instrs {
		o.Write("\t")
		switch v := instr.(type) {
		case ssa.Value:
			// Left-align the instruction.
			if name := v.Name(); name != "" {
				o.Write("%s = ", name)
			}
			o.Write("%s", instr.String())
		case nil:
			o.Write("<deleted>")
		default:
			o.Write("%s", instr.String())
		}
		o.Write("\n")
	}
}
