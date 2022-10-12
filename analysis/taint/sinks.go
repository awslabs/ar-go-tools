package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/ssa"
)

// NewSinkMap builds a SinkMap by inspecting the ssa for each function inside each package.
func NewSinkMap(c *config.Config, pkgs []*ssa.Package) PackageToNodes {
	return newPackagesMap(c, pkgs, isSinkNode)
}

func isSinkNode(cfg *config.Config, n *ssa.Node) bool {
	switch node := (*n).(type) {
	// Look for calls to functions that are considered sinks
	case *ssa.Call:
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg, err := FindSafeCalleePkg(node)
			if err != nil {
				return false // skip if we can't get the package
			} else {
				return cfg.IsSink(config.CodeIdentifier{Package: calleePkg, Method: methodName, Receiver: receiver})
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg, err := FindSafeCalleePkg(node)
			if err != nil {
				return false // skip if we can't get the package
			} else {
				return cfg.IsSink(config.CodeIdentifier{Package: calleePkg, Method: funcValue})
			}
		}
	// We will likely extend the functionality to other types of sinks
	default:
		return false
	}
}
