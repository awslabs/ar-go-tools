package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// NewSinkMap builds a SinkMap by inspecting the ssa for each function inside each package.
func NewSinkMap(c *config.Config, pkgs []*ssa.Package) dataflow.PackageToNodes {
	return dataflow.NewPackagesMap(c, pkgs, isSinkNode)
}

func isSink(n dataflow.GraphNode, cfg *config.Config) bool {
	switch n := n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode:
		// A these nodes are never a sink; the sink will be identified at the call site, not the callee definition.
		return false
	case *dataflow.CallNodeArg:
		// A call node argument is a sink if the callee is a sink
		return isSink(n.Parent(), cfg)
	case *dataflow.CallNode:
		return isSinkNode(cfg, n.CallSite().(ssa.Node))
	case *dataflow.SyntheticNode:
		return isSinkNode(cfg, n.Instr().(ssa.Node)) // safe type conversion
	case *dataflow.ReturnNode, *dataflow.ClosureNode, *dataflow.BoundVarNode:
		return false
	default:
		return false
	}
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
				calleePkg, err := dataflow.FindSafeCalleePkg(callCommon)
				if err != nil {
					return false // skip if we can't get the package
				} else {
					return cfg.IsSink(config.CodeIdentifier{Package: calleePkg, Method: methodName, Receiver: receiver})
				}
			} else {
				funcValue := callCommon.Value.Name()
				calleePkg, err := dataflow.FindSafeCalleePkg(callCommon)
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
