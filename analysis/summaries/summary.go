// Package summaries defines how data flow information can be summarized for a given function.
// These summaries are only for pre-determined functions (e.g. standard library functions) and are not computed during the analysis.
package summaries

import (
	"strings"

	"github.com/awslabs/argot/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

// Summary summarizes data flow information for a function.
// This makes an analysis faster because it does not have to compute this information for the pre-summarized functions.
type Summary struct {
	// Args is an array A that maps input argument positions to the arguments that are tainted
	// if the input argument is tainted. For example,  A[0] = [0,1] means that if the first argument
	// of the function is tainted, then when the function returns, the first and the last argument
	// are tainted. TODO word this better for data flows (and not taints)
	// A[1] = [] means that the second argument is sanitized.
	// A[1] = [1] means that the taint on the second argument is conserved, but no other argument is tainted.
	Args [][]int
	// Rets is an array A that links information between input arguments and outputs.
	// A[0] = [0] marks a data flow from argument 0 to the first returned value.
	Rets [][]int
}

// NoDataFlowPropagation is a summary for functions that do not have a data flow. The return value, if used, is a
// sanitized value.
var NoDataFlowPropagation = Summary{Rets: [][]int{}, Args: [][]int{}}

// SingleVarArgPropagation is a summary for functions that have a single variadic argument (func f(arg ..any) {...})
// This will propagate the data flow to the return value.
var SingleVarArgPropagation = Summary{Args: [][]int{{0}}, Rets: [][]int{{0}}}

// TwoArgPropagation is a summary for functions that have two arguments and both propagate their data to the return
// value, but there is no dataflow between arguments.
var TwoArgPropagation = Summary{Args: [][]int{{0}, {1}}, Rets: [][]int{{0}, {0}}}

// FormatterPropagation is a summary for functions like Printf where the first and second arguments might be tainted,
// and this will taint the returned value (for example: an error, a string with Sprintf).
var FormatterPropagation = Summary{Args: [][]int{{0}, {1}}, Rets: [][]int{{0}, {0}}}

// IsStdPackage returns true if the input package is in the standard library or the runtime. The standard library
// is defined internally as the list of packages in summaries.stdPackages
//
// Return false if the input is nil.
func IsStdPackage(pkg *ssa.Package) bool {
	if pkg == nil {
		return false
	}
	pkgPath := pkg.Pkg.Path()
	return IsStdPackageName(pkgPath)
}

func IsStdPackageName(name string) bool {
	_, ok := stdPackages[name]
	return ok || strings.HasPrefix(name, "runtime")
}

// IsStdFunction returns true if the input function is a function from the standard library or the runtime.
//
// Returns false if the input is nil.
func IsStdFunction(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	pkgName := packagescan.PackageNameFromFunction(function)
	_, ok := stdPackages[pkgName]
	return ok || strings.HasPrefix(pkgName, "runtime")
}

// IsSummaryRequired returns true if the summary of function is needed to build a sound analysis.
// For example, sync.Once.Do needs to be summarized because its argument will be called only inside the function,
// and therefore, it cannot be stubbed out.
func IsSummaryRequired(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	return requiredSummaries[function.String()]
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
	pkgName := packagescan.PackageNameFromFunction(function)
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

// IsUserDefinedFunction returns true when function is a user-defined function. A function is considered
// to be user-defined if it is not in the standard library (in summaries.stdPackages) or in the runtime.
// For example, the functions in the non-standard library packages are considered user-defined.
func IsUserDefinedFunction(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	pkgKey := packagescan.PackageNameFromFunction(function)

	if pkgKey == "" {
		return false
	}
	// Check that it is not in a standard lib package
	return !IsStdPackageName(pkgKey)
}
