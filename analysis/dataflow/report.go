package dataflow

import (
	"fmt"
	"golang.org/x/tools/go/ssa"
	"os"
)

func (c *Cache) ReportNoCallee(instr ssa.CallInstruction) {
	pos := c.Program.Fset.Position(instr.Pos())

	if c.Config.ReportNoCalleeSites {
		f, err := os.OpenFile(c.Config.ReportNoCalleeFile(), os.O_APPEND, 0644)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Could not open %s\n", c.Config.ReportNoCalleeFile())
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
