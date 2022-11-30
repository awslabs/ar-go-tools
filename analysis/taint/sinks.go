package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/ssa"
)

// NewSinkMap builds a SinkMap by inspecting the ssa for each function inside each package.
func NewSinkMap(c *config.Config, pkgs []*ssa.Package) PackageToNodes {
	return newPackagesMap(c, pkgs, isSinkNode)
}

func isSinkNode(cfg *config.Config, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sinks
	case *ssa.Call, *ssa.Go, *ssa.Defer:
		// This condition should always be true
		if callNode, ok := node.(ssa.CallInstruction); ok {
			callCommon := callNode.Common()
			if callCommon.IsInvoke() {
				receiver := callCommon.Value.Name()
				methodName := callCommon.Method.Name()
				calleePkg, err := FindSafeCalleePkg(callCommon)
				if err != nil {
					return false // skip if we can't get the package
				} else {
					return cfg.IsSink(config.CodeIdentifier{Package: calleePkg, Method: methodName, Receiver: receiver})
				}
			} else {
				funcValue := callCommon.Value.Name()
				calleePkg, err := FindSafeCalleePkg(callCommon)
				if err != nil {
					return false // skip if we can't get the package
				} else {
					return cfg.IsSink(config.CodeIdentifier{Package: calleePkg, Method: funcValue})
				}
			}
		}
		return false
	// We will likely extend the functionality to other types of sinks
	default:
		return false
	}
}
