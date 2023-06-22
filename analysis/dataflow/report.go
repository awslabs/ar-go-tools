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

	"golang.org/x/tools/go/ssa"
)

func (c *AnalyzerState) ReportNoCallee(instr ssa.CallInstruction) {
	pos := c.Program.Fset.Position(instr.Pos())

	if c.Config.ReportNoCalleeSites {
		f, err := os.OpenFile(c.Config.ReportNoCalleeFile(), os.O_APPEND, 0644)
		if err == nil {
			c.Logger.Errorf("Could not open %s\n", c.Config.ReportNoCalleeFile())
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\"%s\", %s", instr.String(), pos))
	}

	c.Logger.Warnf("No callee found for %s.\n", instr.String())
	c.Logger.Warnf("Location: %s.\n", pos)
	if instr.Value() != nil {
		c.Logger.Warnf("Value: %s\n", instr.Value().String())
		c.Logger.Warnf("Type: %s\n", instr.Value().Type())
	} else {
		c.Logger.Warnf("Type: %s\n", instr.Common().Value.Type())
	}

	c.Logger.Warnf("Method: %s\n", instr.Common().Method)
}
