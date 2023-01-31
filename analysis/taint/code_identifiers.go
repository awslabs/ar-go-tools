package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

// NewSourceMap builds a SourceMap by inspecting the ssa for each function inside each package.
func NewSourceMap(c *config.Config, pkgs []*ssa.Package) dataflow.PackageToNodes {
	return dataflow.NewPackagesMap(c, pkgs, isSourceNode)
}

// NewSinkMap builds a SinkMap by inspecting the ssa for each function inside each package.
func NewSinkMap(c *config.Config, pkgs []*ssa.Package) dataflow.PackageToNodes {
	return dataflow.NewPackagesMap(c, pkgs, isSinkNode)
}

func isSourceNode(cfg *config.Config, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sources
	case *ssa.Call:
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg.Value(), Method: methodName, Receiver: receiver})
			} else {
				return false
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg.Value(), Method: funcValue})
			} else {
				return false
			}
		}

	// Field accesses that are considered as sources
	case *ssa.Field:
		fieldName := dataflow.FieldFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	case *ssa.FieldAddr:
		fieldName := dataflow.FieldAddrFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	// Allocations of data of a type that is a source
	case *ssa.Alloc:
		packageName, typeName, err := dataflow.FindTypePackage(node.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Type: typeName})
		}

	default:
		return false
	}
}

func isSinkNode(cfg *config.Config, n ssa.Node) bool {
	return isMatchingCodeIdWithCallee(cfg.IsSink, nil, n)
}

func isSink(n dataflow.GraphNode, cfg *config.Config) bool {
	return isMatchingCodeId(cfg.IsSink, n)
}

func isSanitizer(n dataflow.GraphNode, cfg *config.Config) bool {
	return isMatchingCodeId(cfg.IsSanitizer, n)
}

func isMatchingCodeId(codeIdOracle func(config.CodeIdentifier) bool, n dataflow.GraphNode) bool {
	switch n := n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode:
		// A these nodes are never a sink; the sink will be identified at the call site, not the callee definition.
		return false
	case *dataflow.CallNodeArg:
		// A call node argument is a sink if the callee is a sink
		return isMatchingCodeId(codeIdOracle, n.ParentNode())
	case *dataflow.CallNode:
		return isMatchingCodeIdWithCallee(codeIdOracle, n.Callee(), n.CallSite().(ssa.Node))
	case *dataflow.SyntheticNode:
		return isMatchingCodeIdWithCallee(codeIdOracle, nil, n.Instr().(ssa.Node)) // safe type conversion
	case *dataflow.ReturnNode, *dataflow.ClosureNode, *dataflow.BoundVarNode:
		return false
	default:
		return false
	}
}

// isIdentifiedNodeWithCallee returns true when the node n with callee matches an identifier according to the predicate
// codeIdOracle
func isMatchingCodeIdWithCallee(codeIdOracle func(config.CodeIdentifier) bool, callee *ssa.Function, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sinks
	case *ssa.Call, *ssa.Go, *ssa.Defer:
		// This condition should always be true
		if callNode, ok := node.(ssa.CallInstruction); ok {
			callCommon := callNode.Common()
			if callCommon.IsInvoke() {
				receiver := callCommon.Value.Name()
				methodName := callCommon.Method.Name()
				maybePkg := dataflow.FindSafeCalleePkg(callCommon)
				if maybePkg.IsSome() {
					return codeIdOracle(config.CodeIdentifier{
						Package: maybePkg.Value(), Method: methodName, Receiver: receiver,
					})
				} else if callee != nil {
					pkgName := packagescan.PackageNameFromFunction(callee)
					return codeIdOracle(config.CodeIdentifier{
						Package: pkgName, Method: methodName, Receiver: receiver,
					})
				} else {
					return false
				}
			} else {
				funcName := callCommon.Value.Name()
				maybePkg := dataflow.FindSafeCalleePkg(callCommon)
				if maybePkg.IsSome() {
					return codeIdOracle(config.CodeIdentifier{Package: maybePkg.Value(), Method: funcName})
				} else if callee != nil {
					pkgName := packagescan.PackageNameFromFunction(callee)
					return codeIdOracle(config.CodeIdentifier{
						Package: pkgName, Method: funcName,
					})
				} else {
					return false
				}
			}
		}
		return false
	// We will likely extend the functionality to other types of sanitizers
	default:
		return false
	}
}
