package summaries

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"golang.org/x/tools/go/ssa"
	"strings"
)

// Summary summarizes taint-flow information for a function.
type Summary struct {
	// TaintingArgs is an array A that maps input argument positions to the arguments that are tainted
	// if the input argument is tainted. For example,  A[0] = [0,1] means that if the first argument
	// of the function is tainted, then when the function returns, the first and the last argument
	// are tainted.
	// A[1] = [] means that the second argument is sanitized.
	// A[1] = [1] means that the taint on the second argument is conserved, but no other argument is tainted.
	TaintingArgs [][]int
	// TaintingRets is an array A that links information between input arguments and outputs.
	// A[0] = [0] means that if argument 0 is tainted, then the first returned value is also tainted.
	TaintingRets [][]int
}

// NoTaintPropagation is a summary for functions that do not propagate the taint. The return value, is used, is a
// sanitized value.
var NoTaintPropagation = Summary{TaintingRets: [][]int{}, TaintingArgs: [][]int{}}

// SingleVarArgPropagation is a summary for functions that have a single variadic argument (func f(arg ..any) {...})
// This will propagate the taint to the return value.
var SingleVarArgPropagation = Summary{TaintingArgs: [][]int{{0}}, TaintingRets: [][]int{{0}}}

// FormatterPropagation is a summary for functions like Printf where the second argument might be tainted,
// and this will taint the returned value (for example, an error, a string with Sprintf
var FormatterPropagation = Summary{TaintingArgs: [][]int{{}, {0}}, TaintingRets: [][]int{{}, {0}}}

// IsStdPackage returns true if the input package is in the standard library or the runtime. The standard library
// is defined internally as the list of packages in summaries.stdPackages
//
// Return false if the input is nil.
func IsStdPackage(pkg *ssa.Package) bool {
	if pkg == nil {
		return false
	}
	pkgPath := pkg.Pkg.Path()
	_, okStd := stdPackages[pkgPath]
	return okStd || strings.HasPrefix(pkg.Pkg.Path(), "runtime")
}

// IsStdFunction returns true if the input function is a function from the standard library or the runtime.
//
// Returns false if the input is nil.
func IsStdFunction(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	pkgName := analysis.PackageNameFromFunction(function)
	_, ok := stdPackages[pkgName]
	return ok || strings.HasPrefix(pkgName, "runtime")
}

// PkgHasSummaries returns true if the input package has summaries. A package has summaries if it is present in either
// the stdPackages map or the OtherPackages map that define summaries in the summaries package.
//
// Returns false if the input package is nil.
func PkgHasSummaries(pkg *ssa.Package) bool {
	if pkg == nil {
		return false
	}
	pkgPath := pkg.Pkg.Path()
	_, okStd := stdPackages[pkgPath]
	_, okOther := OtherPackages[pkgPath]
	return okStd || okOther
}

// SummaryOfFunc returns the summary of function and true if function has a summary,
// otherwise it returns an empty summary and false.
//
// Returns (Summary{}, false) if function is nil.
func SummaryOfFunc(function *ssa.Function) (Summary, bool) {
	if function == nil {
		return Summary{}, false
	}
	pkgName := analysis.PackageNameFromFunction(function)
	if s, ok := stdPackages[pkgName]; ok {
		summary, ok := s[function.String()]
		return summary, ok
	}

	if s, ok := OtherPackages[pkgName]; ok {
		summary, ok := s[function.String()]
		return summary, ok
	}

	return Summary{}, false
}
