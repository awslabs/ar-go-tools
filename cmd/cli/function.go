package main

import (
	"fmt"
	"regexp"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"golang.org/x/term"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// cmdFocus puts a given function into focus by setting state.CurrentFunction
func cmdFocus(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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
func cmdPackage(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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

	pkgName := packagescan.PackageNameFromFunction(state.CurrentFunction)
	writeFmt(tt, "Package %s:\n", pkgName)
	pkg := packagescan.PackageTypeFromFunction(state.CurrentFunction)
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
func cmdUnfocus(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
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
func cmdSsaValue(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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
			if matchInstr(r, instr) {
				showInstr(tt, c, instr)
			}
		}
	}
	return false
}

// cmdWhere prints the position of a function
func cmdWhere(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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
			cmdWhere(tt, nil, command)
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

func matchValue(r *regexp.Regexp, val ssa.Value) bool {
	return r.MatchString(val.String()) || r.MatchString(val.Name())
}

func matchInstr(r *regexp.Regexp, instr ssa.Instruction) bool {
	b := r.MatchString(instr.String())
	if val, isVal := instr.(ssa.Value); isVal {
		b = b || r.MatchString(val.Name())
	}
	return b
}

func showValue(tt *term.Terminal, c *dataflow.Cache, val ssa.Value) {
	writeFmt(tt, "Matching value: %s\n", val.Name())
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
		if label.Value() != nil {
			entries = append(entries,
				displayElement{content: "[" + label.Value().Name() + "]", escape: tt.Escape.Yellow})
		}
	}
	writeEntries(tt, entries, "    ")
}

func showInstr(tt *term.Terminal, c *dataflow.Cache, instr ssa.Instruction) {
	if val, isVal := instr.(ssa.Value); isVal {
		showValue(tt, c, val)
	} else {
		writeFmt(tt, "Matching instruction: %s\n", instr.String())
		writeFmt(tt, "            location: %s\n", c.Program.Fset.Position(instr.Pos()))
	}
}
