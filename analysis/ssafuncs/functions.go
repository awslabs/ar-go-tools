package ssafuncs

import (
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

func CollectPkgFunctions(pkg *ssa.Package, functions map[*ssa.Function]struct{}) {
	for _, member := range pkg.Members {
		switch pkgM := member.(type) {
		case *ssa.Function:
			functions[pkgM] = struct{}{}
		case *ssa.Type:
			methods := typeutil.IntuitiveMethodSet(pkgM.Type(), &pkg.Prog.MethodSets)
			for _, sel := range methods {
				functionMethod := pkg.Prog.MethodValue(sel)
				if functionMethod != nil {
					functions[functionMethod] = struct{}{}
				}
			}
		}
	}
}

func CollectProgFunctions(prog *ssa.Program) map[*ssa.Function]struct{} {
	functions := make(map[*ssa.Function]struct{})
	for _, pkg := range prog.AllPackages() {
		CollectPkgFunctions(pkg, functions)
	}
	return functions
}

func IterateInstructions(function *ssa.Function, f func(instruction *ssa.Instruction)) {
	// If this is an external function, return.
	if function.Blocks == nil {
		return
	}

	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			f(&instruction)
		}
	}
}
