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

// Package summaries defines how data flow information can be summarized for a given function.
// These summaries are only for pre-determined functions (e.g. standard library functions) and are not computed during the analysis.
package summaries

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// A Summarizer is a summary that exposes the necessary functionality to build a dataflow summary from it.
// The basic Summary and the DetailedSummary expose this interface.
type Summarizer interface {
	// GetArgFlows returns a matrix of integers that represent the directed flow edges betwen the functions
	// argument indices.
	GetArgFlows(f *ssa.Function) ([][]int, error)
	// GetReturnFlows returns a matrix of integers that reprsent the directed flow edges between the function's
	// arguments and the return tuple indices
	GetReturnFlows(f *ssa.Function) ([][]int, error)
}

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

// GetArgFlows for the summary simply returns the Args field.
func (s Summary) GetArgFlows(_ *ssa.Function) ([][]int, error) {
	return s.Args, nil
}

// GetReturnFlows for the summary simply returns the Rets field.
func (s Summary) GetReturnFlows(_ *ssa.Function) ([][]int, error) {
	return s.Rets, nil
}

// NoDataFlowPropagation is a summary for functions that do not have a data flow. The return value, if used, is a
// sanitized value.
var NoDataFlowPropagation = Summary{Rets: [][]int{}, Args: [][]int{}}

// SingleVarArgPropagation is a summary for functions that have a single (possibly variadic) argument (func f(arg ..any) any {...})
// This will propagate the data flow to the return value.
var SingleVarArgPropagation = Summary{Args: [][]int{{0}}, Rets: [][]int{{0}}}

// SingleVarArgTwoRetsPropagation is a summary for functions that have a single variadic argument (func f(arg ..any) (any,any) {...})
// This will propagate the data flow to both return values.
var SingleVarArgTwoRetsPropagation = Summary{Args: [][]int{{0}}, Rets: [][]int{{0, 1}}}

// TwoArgPropagation is a summary for functions that have two arguments and both propagate their data to the return
// value, but there is no dataflow between arguments.
var TwoArgPropagation = Summary{Args: [][]int{{0}, {1}}, Rets: [][]int{{0}, {0}}}

// TwoArgReceivePropagation is a summary for functions that have two arguments and both propagate their data to the return
// value, and the second argument propagates to the first (typically, functions where the first argument is the receiver)
var TwoArgReceivePropagation = Summary{Args: [][]int{{0}, {1}}, Rets: [][]int{{0}, {0}}}

// FormatterPropagation is a summary for functions like Printf where the first and second arguments might be tainted,
// and this will taint the returned value (for example: an error, a string with Sprintf).
var FormatterPropagation = Summary{Args: [][]int{{0}, {1}}, Rets: [][]int{{0}, {0}}}

// IsStdPackageName returns true if the package name is a package of the standard library
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
	pkgName := lang.PackageNameFromFunction(function)
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

// PkgHasSummaries returns true if the input package has summaries.
// A package has summaries if it is present in the stdPackages.
//
// Returns false if the input package is nil.
func PkgHasSummaries(pkg *ssa.Package) bool {
	if pkg == nil {
		return false
	}
	pkgPath := pkg.Pkg.Path()
	_, okStd := stdPackages[pkgPath]
	return okStd
}

// SummaryOfFunc returns the summary of function and true if function has a summary,
// otherwise it returns an empty summary and false.
//
// Returns (Summary{}, false) if function is nil.
func SummaryOfFunc(function *ssa.Function) (Summarizer, bool) {
	if function == nil {
		return Summary{}, false
	}
	pkgName := lang.PackageNameFromFunction(function)
	if s, ok := stdPackages[pkgName]; ok {
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
	pkgKey := lang.PackageNameFromFunction(function)

	if pkgKey == "" {
		return false
	}
	// Check that it is not in a standard lib package
	return !IsStdPackageName(pkgKey)
}

const receiverTag = "!receiver"
const argPrefix = "!arg " // always with a space
const argNameLeft = "<"
const argNameRight = ">"
const returnPrefix = "!ret"

// Parses valid names for parameters
var validArgNameRegex = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_]*$")

// rawSummary is a summary of flows for a function where the flow nodes still
// need to be parsed into SummaryNode to form a DetailedSummary.
// A rawSummary is not a Summarizer; it needs to be compiled first.
type rawSummary struct {
	Flows map[string][]string
}

// A detailedSummary is a more human-friendly and more precise version of a summary.
type detailedSummary struct {
	Flows map[SummaryNode][]SummaryNode
}

// GetArgFlows returns the indexed flows from parameters to returns of the detailed summary.
func (s detailedSummary) GetArgFlows(f *ssa.Function) ([][]int, error) {
	nArgs := f.Signature.Params().Len()
	if f.Signature.Recv() != nil {
		nArgs++
	}
	res := make([][]int, nArgs)
	for src, dests := range s.Flows {
		if srcIndex, indexExpected, err := getParamOrRecvIndex(src, f); indexExpected {
			if err != nil {
				return res, fmt.Errorf("failed to load arg flow: %s", err)
			}
			res[srcIndex] = []int{}
			for _, dest := range dests {
				if destIndex, expectIndex, err := getParamOrRecvIndex(dest, f); expectIndex {
					if err != nil {
						return res, fmt.Errorf("failed to load arg flow: %s", err)
					}
					res[srcIndex] = append(res[0], destIndex)
				}
			}
		}
	}
	return res, nil
}

// GetReturnFlows returns the indexed flows from parameter to returns of the detailed summary.
func (s detailedSummary) GetReturnFlows(f *ssa.Function) ([][]int, error) {
	nArgs := f.Signature.Params().Len()
	if f.Signature.Recv() != nil {
		nArgs++
	}
	res := make([][]int, nArgs)
	for src, dests := range s.Flows {
		if srcIndex, expectIndex, err := getParamOrRecvIndex(src, f); expectIndex {
			if err != nil {
				return res, fmt.Errorf("cannot get return flows: %s", err)
			}
			res[srcIndex] = []int{}
			for _, dest := range dests {
				if retIndex, ok := dest.(ReturnSNode); ok {
					res[srcIndex] = append(res[srcIndex], retIndex.Index)
				}
			}
		}
	}
	return res, nil
}

// getParamOrRecvIndex retrieves the index of the parameter corresponding to the summary node
// in the given function.
// It returns a triple where the first element is the index, the second element is a boolean
// indicating whether the summary node is expected to have an argumnet index, and last an error
// that is  returned when the summary node is expected to have an index but there was an error
// computing it.
func getParamOrRecvIndex(n SummaryNode, f *ssa.Function) (int, bool, error) {
	switch n := n.(type) {
	case ReceiverSNode:
		if f.Signature.Recv() == nil {
			return -1, true, fmt.Errorf("function %s does not have a receiver", f.String())
		}
		return 0, true, nil
	case ArgumentSNode:
		// By name if name is non-empty
		if n.Name != "" {
			for i := 0; i < f.Signature.Params().Len(); i++ {
				if f.Signature.Params().At(i).Name() == n.Name {
					return i, true, nil
				}
			}
			return -1, false, fmt.Errorf("function %s does not have an argument named %s", f.String(), n.Name)
		}
		// by index
		if f.Signature.Recv() == nil {
			return n.Index, true, nil
		}
		return n.Index + 1, true, nil
	default:
		// not a parameter
		return -1, false, nil
	}
}

// compile parses the raw summary as a map from string representation of summary
// nodes to list of summary nodes to its parsed version using structs.
func (s rawSummary) compile() (detailedSummary, error) {
	flows := make(map[SummaryNode][]SummaryNode)
	for k, vals := range s.Flows {
		key, err := ParseSummaryNode(k)
		if err != nil {
			return detailedSummary{}, err
		}
		if _, isReturnNode := key.(ReturnSNode); isReturnNode {
			return detailedSummary{}, fmt.Errorf("data cannot flow from a return node")
		}
		flows[key] = make([]SummaryNode, len(vals))
		for _, v := range vals {
			value, err := ParseSummaryNode(v)
			if err != nil {
				return detailedSummary{}, err
			}
			flows[key] = append(flows[key], value)
		}
	}
	return detailedSummary{Flows: flows}, nil
}

// mustCompile is the version of IntoDetailedSummary that panics instead of returning an error.
func (s rawSummary) mustCompile() detailedSummary {
	f, err := s.compile()
	if err != nil {
		panic(err)
	}
	return f
}

// A SummaryNode is a dataflow node that can be specified in a summary:
// Those nodes are:
// - receiver nodes,
// - argument nodes,
// - return nodes.
// Typically we do not allow to express internal call nodes in the summary.
type SummaryNode interface {
	fmt.Stringer
	WithObjectPath(path string) SummaryNode
}

// ParseSummaryNode parses the string representation of a summary node.
// A summary node is represented by a string (<base>)objectPath, or <base> where base can be:
//
// - !receiver for a receiver,
// - !arg <name> for an argument selected by name,
// - !arg i for an argument selected by index i,
// - !ret i for a return, where i is the tuple index.
//
// The objectPath is the field or array path specifier, always after a closing parenthesis.
func ParseSummaryNode(summary string) (SummaryNode, error) {
	if strings.HasPrefix(summary, "(") {
		// object path
		baseRepr, opath, ok := strings.Cut(summary[1:], ")")
		if !ok {
			return nil, fmt.Errorf("cannot parse %q", summary)
		}
		baseNode, err := ParseSummaryNode(baseRepr)
		if err != nil {
			return nil, err
		}
		// TODO: some validation on the object path
		return baseNode.WithObjectPath(opath), nil
	}

	if strings.HasPrefix(summary, argPrefix) {
		// should be of the form !arg "name" or !arg index
		s := strings.TrimPrefix(summary, argPrefix)
		if strings.HasPrefix(s, argNameLeft) && strings.HasSuffix(s, argNameRight) {
			s = strings.TrimPrefix(s, argNameLeft)
			s = strings.TrimSuffix(s, argNameRight)
			// check that s is a valid name
			if !validArgNameRegex.MatchString(s) {
				return nil, fmt.Errorf(
					"cannot parse %q because %q is not a valid argument name",
					summary, s,
				)
			}
			return ArgumentSNode{Name: s}, nil
		}
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf(
				"cannot parse %q because %q is not an integer, or a string between %q and %q",
				summary, s, argNameLeft, argNameRight,
			)
		}
		return ArgumentSNode{Index: i}, nil
	} else if strings.HasPrefix(summary, returnPrefix) {
		// Special case: it's just "ret!" standing for "ret! 0"
		if summary == returnPrefix {
			return ReturnSNode{Index: 0}, nil
		}
		s := strings.TrimPrefix(summary, returnPrefix+" ")
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q because %q is not an integer", summary, s)
		}
		return ReturnSNode{Index: i}, nil
	} else if summary == receiverTag {
		return ReceiverSNode{}, nil
	}

	return nil, fmt.Errorf("cannot parse %q", summary)
}

// ReceiverSNode is the suymmary that corresponds to a receiver. A receiver is a
// special parameter that is the receiver of a method.
type ReceiverSNode struct {
	ObjectPath string
}

// Repr returns the string representation of the node. The returned string can be
// parsed back using ParseSummaryNode
func (r ReceiverSNode) String() string {
	if r.ObjectPath == "" {
		return receiverTag
	}
	return "(" + receiverTag + ")" + r.ObjectPath
}

// WithObjectPath returns the receiver node with the specified object path,
// ignoring the original object path.
func (r ReceiverSNode) WithObjectPath(path string) SummaryNode {
	return ReceiverSNode{ObjectPath: path}
}

// ArgumentSNode is the summary node that corresponds to a argument node. An argument
// node should be specified with either its name or its index.
// Because we represent receivers separately, the index is the parameter index is counted
// from the first non-receiver argument of the function.
type ArgumentSNode struct {
	Name       string
	Index      int
	ObjectPath string
}

// Repr returns the repr of an argument node, which is either !arg i where i is an integer
// or !arg <name> where name is a string, which must be between < and >.
// If the object path is not empty then the base object is wrapped in parentheses and the
// object path is appended.
func (a ArgumentSNode) String() string {
	baseStr := argPrefix
	if a.Name != "" {
		baseStr += argNameLeft + a.Name + argNameRight
	} else {
		baseStr += strconv.Itoa(a.Index)
	}
	if a.ObjectPath != "" {
		baseStr = "(" + baseStr + ")" + a.ObjectPath
	}
	return baseStr
}

// WithObjectPath returns the argument node with the specified object path.
// The original object path is ignored.
func (a ArgumentSNode) WithObjectPath(path string) SummaryNode {
	return ArgumentSNode{Name: a.Name, Index: a.Index, ObjectPath: path}
}

// ReturnSNode is the summary node that corresponds to the return, with
// an index specifying the element of the tuple.
type ReturnSNode struct {
	Index      int
	ObjectPath string
}

// Repr returns the string representation of the node.
// It always return the index reprsentation of the node, although the parsing
// function also accepts the syntax "!ret" as short for "!ret 0"
func (r ReturnSNode) String() string {
	baseStr := returnPrefix + " " + strconv.Itoa(r.Index)
	if r.ObjectPath != "" {
		baseStr = "(" + baseStr + ")" + r.ObjectPath
	}
	return baseStr
}

// WithObjectPath returns the return node with the specified object path,
// ignoring the original object path.
func (r ReturnSNode) WithObjectPath(path string) SummaryNode {
	return ReturnSNode{Index: r.Index, ObjectPath: path}
}
