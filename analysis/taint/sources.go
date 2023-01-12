package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// NewSourceMap builds a SourceMap by inspecting the ssa for each function inside each package.
func NewSourceMap(c *config.Config, pkgs []*ssa.Package) dataflow.PackageToNodes {
	return dataflow.NewPackagesMap(c, pkgs, isSourceNode)
}

func isSourceNode(cfg *config.Config, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sources
	case *ssa.Call:
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg, err := dataflow.FindSafeCalleePkg(node.Common())
			if err != nil {
				return false // skip if we can't get the package
			} else {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg, Method: methodName, Receiver: receiver})
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg, err := dataflow.FindSafeCalleePkg(node.Common())
			if err != nil {
				return false // skip if we can't get the package
			} else {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg, Method: funcValue})
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
