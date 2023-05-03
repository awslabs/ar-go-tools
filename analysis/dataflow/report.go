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

package dataflow

import (
	"fmt"
	"os"

	"github.com/awslabs/argot/analysis/lang"
	"github.com/awslabs/argot/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

func (c *AnalyzerState) ReportNoCallee(instr ssa.CallInstruction) {
	pos := c.Program.Fset.Position(instr.Pos())

	if c.Config.ReportNoCalleeSites {
		f, err := os.OpenFile(c.Config.ReportNoCalleeFile(), os.O_APPEND, 0644)
		if err == nil {
			c.Err.Printf("Could not open %s\n", c.Config.ReportNoCalleeFile())
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\"%s\", %s", instr.String(), pos))
	}

	if c.Config.Verbose {
		c.Logger.Printf("No callee found for %s.\n", instr.String())
		c.Logger.Printf("Location: %s.\n", pos)
		if instr.Value() != nil {
			c.Logger.Printf("Value: %s\n", instr.Value().String())
			c.Logger.Printf("Type: %s\n", instr.Value().Type())
		} else {
			c.Logger.Printf("Type: %s\n", instr.Common().Value.Type())
		}

		c.Logger.Printf("Method: %s\n", instr.Common().Method)
	}
}

func printMissingSummaryMessage(c *AnalyzerState, callSite *CallNode) {
	if !c.Config.Verbose {
		return
	}

	var typeString string
	if callSite.Callee() == nil {
		typeString = fmt.Sprintf("nil callee (in %s)",
			lang.SafeFunctionPos(callSite.Graph().Parent).ValueOr(lang.DummyPos))
	} else {
		typeString = callSite.Callee().Type().String()
	}
	c.Logger.Printf(utils.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
		callSite.String(), typeString)))
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		c.Logger.Printf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))

		pos := callSite.Position(c)
		if pos != lang.DummyPos {
			c.Logger.Printf("|_ See call site: %s", pos)
		} else {
			opos := lang.SafeFunctionPos(callSite.Graph().Parent)
			c.Logger.Printf("|_ See call site in %s", opos.ValueOr(lang.DummyPos))
		}

		methodFunc := callSite.CallSite().Common().Method
		if methodFunc != nil {
			methodKey := callSite.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
			c.Logger.Printf("| Or add %s to dataflow contracts", methodKey)
		}
	}
}

func printMissingClosureSummaryMessage(s *AnalyzerState, bl *BoundLabelNode) {
	if !s.Config.Verbose {
		return
	}

	var instrStr string
	if bl.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = bl.Instr().String()
	}
	s.Logger.Printf(utils.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		bl.String(), instrStr)))
	if bl.Instr() != nil {
		s.Logger.Printf("| Please add closure for %s to summaries",
			bl.Instr().String())
		s.Logger.Printf("|_ See closure: %s", bl.Position(s))
	}
}

func printMissingClosureNodeSummaryMessage(s *AnalyzerState, closureNode *ClosureNode) {
	if !s.Config.Verbose {
		return
	}

	var instrStr string
	if closureNode.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = closureNode.Instr().String()
	}
	s.Logger.Printf(utils.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		closureNode.String(), instrStr)))
	if closureNode.Instr() != nil {
		s.Logger.Printf("| Please add closure %s to summaries",
			closureNode.Instr().Fn.String())
		s.Logger.Printf("|_ See closure: %s", closureNode.Position(s))
	}
}

func printWarningSummaryNotConstructed(c *AnalyzerState, callSite *CallNode) {
	if !c.Config.Verbose {
		return
	}

	c.Logger.Printf("| %s: summary has not been built for %s.",
		utils.Yellow("WARNING"),
		utils.Yellow(callSite.Graph().Parent.Name()))
	pos := callSite.Position(c)
	if pos != lang.DummyPos {
		c.Logger.Printf(fmt.Sprintf("|_ See call site: %s", pos))
	} else {
		opos := lang.SafeFunctionPos(callSite.Graph().Parent)
		c.Logger.Printf(fmt.Sprintf("|_ See call site in %s", opos.ValueOr(lang.DummyPos)))
	}

	if callSite.CallSite() != nil {
		methodKey := lang.InstrMethodKey(callSite.CallSite())
		if methodKey.IsSome() {
			c.Logger.Printf(fmt.Sprintf("| Or add %s to dataflow contracts", methodKey.ValueOr("?")))
		}
	}
}
