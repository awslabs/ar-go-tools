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

// Package analysisutil contains utility functions for the analyses in argot.
// These functions are in an internal package because they are not important
// enough to be included in the main library.
package analysisutil

import (
	"fmt"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"golang.org/x/tools/go/ssa"
)

// IsEntrypointNode returns true if n is an entrypoint to the intra-procedural analysis according to f.
func IsEntrypointNode(cfg *config.Config, n ssa.Node, f func(config.Config, config.CodeIdentifier) bool) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entrypoints
	case *ssa.Call:
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return f(*cfg, config.CodeIdentifier{Package: calleePkg.Value(), Method: methodName, Receiver: receiver})
			} else {
				return false
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return f(*cfg, config.CodeIdentifier{Package: calleePkg.Value(), Method: funcValue})
			} else {
				return false
			}
		}

	// Field accesses that are considered as entrypoints
	case *ssa.Field:
		fieldName := dataflow.FieldFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	case *ssa.FieldAddr:
		fieldName := dataflow.FieldAddrFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	// Allocations of data of a type that is a entrypoint
	case *ssa.Alloc:
		packageName, typeName, err := dataflow.FindTypePackage(node.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Type: typeName})
		}

	default:
		return false
	}
}

// PrintMissingSummaryMessage prints a missing summary message to the cache's logger.
func PrintMissingSummaryMessage(c *dataflow.AnalyzerState, callSite *dataflow.CallNode) {
	if !c.Config.Verbose() {
		return
	}

	var typeString string
	if callSite.Callee() == nil {
		typeString = fmt.Sprintf("nil callee (in %s)",
			lang.SafeFunctionPos(callSite.Graph().Parent).ValueOr(lang.DummyPos))
	} else {
		typeString = callSite.Callee().Type().String()
	}
	c.Logger.Debugf(colors.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
		callSite.String(), typeString)))
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		c.Logger.Debugf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))

		pos := callSite.Position(c)
		if pos != lang.DummyPos {
			c.Logger.Debugf("|_ See call site: %s", pos)
		} else {
			opos := lang.SafeFunctionPos(callSite.Graph().Parent)
			c.Logger.Debugf("|_ See call site in %s", opos.ValueOr(lang.DummyPos))
		}

		methodFunc := callSite.CallSite().Common().Method
		if methodFunc != nil {
			methodKey := callSite.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
			c.Logger.Debugf("| Or add %s to dataflow contracts", methodKey)
		}
	}
}

// PrintMissingClosureNodeSummaryMessage prints a missing closure summary message to the cache's logger.
func PrintMissingClosureSummaryMessage(c *dataflow.AnalyzerState, bl *dataflow.BoundLabelNode) {
	if !c.Config.Verbose() {
		return
	}

	var instrStr string
	if bl.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = bl.Instr().String()
	}
	c.Logger.Debugf(colors.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		bl.String(), instrStr)))
	if bl.Instr() != nil {
		c.Logger.Debugf("| Please add closure for %s to summaries",
			bl.Instr().String())
		c.Logger.Debugf("|_ See closure: %s", bl.Position(c))
	}
}

// PrintMissingClosureNodeSummaryMessage prints a missing closure node summary message to the cache's logger.
func PrintMissingClosureNodeSummaryMessage(c *dataflow.AnalyzerState, closureNode *dataflow.ClosureNode) {
	if !c.Config.Verbose() {
		return
	}

	var instrStr string
	if closureNode.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = closureNode.Instr().String()
	}
	c.Logger.Debugf(colors.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		closureNode.String(), instrStr)))
	if closureNode.Instr() != nil {
		c.Logger.Debugf("| Please add closure %s to summaries",
			closureNode.Instr().Fn.String())
		c.Logger.Debugf("|_ See closure: %s", closureNode.Position(c))
	}
}

// PrintWarningSummaryNotConstructed prints a warning message to the cache's logger.
func PrintWarningSummaryNotConstructed(c *dataflow.AnalyzerState, callSite *dataflow.CallNode) {
	if !c.Config.Verbose() {
		return
	}

	c.Logger.Debugf("| %s: summary has not been built for %s.",
		colors.Yellow("WARNING"),
		colors.Yellow(callSite.Graph().Parent.Name()))
	pos := callSite.Position(c)
	if pos != lang.DummyPos {
		c.Logger.Debugf(fmt.Sprintf("|_ See call site: %s", pos))
	} else {
		opos := lang.SafeFunctionPos(callSite.Graph().Parent)
		c.Logger.Debugf(fmt.Sprintf("|_ See call site in %s", opos.ValueOr(lang.DummyPos)))
	}

	if callSite.CallSite() != nil {
		methodKey := lang.InstrMethodKey(callSite.CallSite())
		if methodKey.IsSome() {
			c.Logger.Debugf(fmt.Sprintf("| Or add %s to dataflow contracts", methodKey.ValueOr("?")))
		}
	}
}

// CheckIndex checks that the indexed graph node is valid in the parent node call site
func CheckIndex(c *dataflow.AnalyzerState, node dataflow.IndexedGraphNode, callSite *dataflow.CallNode, msg string) error {
	if node.Index() >= len(callSite.Args()) {
		pos := c.Program.Fset.Position(callSite.CallSite().Value().Pos())
		c.Logger.Debugf("%s: trying to access index %d of %s, which has"+
			" only %d elements\nSee: %s\n", msg, node.Index(), callSite.String(), len(callSite.Args()),
			pos)
		return fmt.Errorf("bad index %d at %s", node.Index(), pos)
	}
	return nil
}

// CheckClosureReturns returns true if returnNode's summary is the same as closureNode's.
func CheckClosureReturns(returnNode *dataflow.ReturnValNode, closureNode *dataflow.ClosureNode) bool {
	if returnNode.Graph() == closureNode.ClosureSummary {
		return true
	}
	return false
}

// CheckNoGoRoutine logs a message if node's callsite is a goroutine.
func CheckNoGoRoutine(s *dataflow.AnalyzerState, reportedLocs map[*ssa.Go]bool, node *dataflow.CallNode) {
	if s.Config.UseEscapeAnalysis {
		return // escape analysis will handle any unsoundness, so there is no need to report
	}

	if goroutine, isGo := node.CallSite().(*ssa.Go); isGo {
		if !reportedLocs[goroutine] {
			reportedLocs[goroutine] = true
			s.Logger.Warnf(colors.Yellow("Data flows to Go call."))
			s.Logger.Warnf("-> Position: %s", node.Position(s))
		}
	}
}
