package dataflow

import (
	"fmt"
	"os"

	"github.com/awslabs/argot/analysis/format"
	"github.com/awslabs/argot/analysis/packagescan"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"golang.org/x/tools/go/ssa"
)

func (c *Cache) ReportNoCallee(instr ssa.CallInstruction) {
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

func printMissingSummaryMessage(c *Cache, callSite *CallNode) {
	if !c.Config.Verbose {
		return
	}

	var typeString string
	if callSite.Callee() == nil {
		typeString = fmt.Sprintf("nil callee (in %s)",
			packagescan.SafeFunctionPos(callSite.Graph().Parent).ValueOr(packagescan.DummyPos))
	} else {
		typeString = callSite.Callee().Type().String()
	}
	c.Logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
		callSite.String(), typeString)))
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		c.Logger.Printf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))

		pos := callSite.Position(c)
		if pos != packagescan.DummyPos {
			c.Logger.Printf("|_ See call site: %s", pos)
		} else {
			opos := packagescan.SafeFunctionPos(callSite.Graph().Parent)
			c.Logger.Printf("|_ See call site in %s", opos.ValueOr(packagescan.DummyPos))
		}

		methodFunc := callSite.CallSite().Common().Method
		if methodFunc != nil {
			methodKey := callSite.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
			c.Logger.Printf("| Or add %s to dataflow contracts", methodKey)
		}
	}
}

func printMissingClosureSummaryMessage(c *Cache, closureNode *ClosureNode) {
	if !c.Config.Verbose {
		return
	}

	var instrStr string
	if closureNode.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = closureNode.Instr().String()
	}
	c.Logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		closureNode.String(), instrStr)))
	if closureNode.Instr() != nil {
		c.Logger.Printf("| Please add closure %s to summaries",
			closureNode.Instr().Fn.String())
		c.Logger.Printf("|_ See closure: %s", closureNode.Position(c))
	}
}

func printWarningSummaryNotConstructed(c *Cache, callSite *CallNode) {
	if !c.Config.Verbose {
		return
	}

	c.Logger.Printf("| %s: summary has not been built for %s.",
		format.Yellow("WARNING"),
		format.Yellow(callSite.Graph().Parent.Name()))
	pos := callSite.Position(c)
	if pos != packagescan.DummyPos {
		c.Logger.Printf(fmt.Sprintf("|_ See call site: %s", pos))
	} else {
		opos := packagescan.SafeFunctionPos(callSite.Graph().Parent)
		c.Logger.Printf(fmt.Sprintf("|_ See call site in %s", opos.ValueOr(packagescan.DummyPos)))
	}

	if callSite.CallSite() != nil {
		methodKey := ssafuncs.InstrMethodKey(callSite.CallSite())
		if methodKey.IsSome() {
			c.Logger.Printf(fmt.Sprintf("| Or add %s to dataflow contracts", methodKey.ValueOr("?")))
		}
	}
}
