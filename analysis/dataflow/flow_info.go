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
	"io"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// FlowInformation contains the dataflow information necessary for the analysis and function summary building.
type FlowInformation struct {
	// Function is the function being analyzed
	Function *ssa.Function

	// user provided configuration identifying specific dataflow nodes to track and other settings (e.g. verbosity)
	Config *config.Config

	// MarkedValues maps instructions to abstract states, i.e. a map from values to their abstract value, which is a
	// set of marks
	MarkedValues map[ssa.Instruction]map[ssa.Value]map[Mark]bool

	// LocSet is a map from marks to the instructions that read or write those marks
	LocSet map[Mark]map[ssa.Instruction]bool
}

// NewFlowInfo returns a new FlowInformation with all maps initialized.
func NewFlowInfo(cfg *config.Config, f *ssa.Function) *FlowInformation {
	return &FlowInformation{
		Function:     f,
		Config:       cfg,
		MarkedValues: make(map[ssa.Instruction]map[ssa.Value]map[Mark]bool),
		LocSet:       make(map[Mark]map[ssa.Instruction]bool),
	}
}

// Show prints the abstract states at each instruction in the function.
func (fi *FlowInformation) Show(w io.Writer) {
	if fi.Function == nil {
		return
	}
	fmt.Fprintf(w, "Function %s:\n", fi.Function.Name())
	lang.IterateInstructions(fi.Function, func(_ int, i ssa.Instruction) { fi.ShowAt(w, i) })
}

// ShowAt pretty-prints the abstract state of the analysis at instruction i. A line is printed for every SSA value with
// an abstract value (a set of marks).
func (fi *FlowInformation) ShowAt(w io.Writer, i ssa.Instruction) {
	fmt.Fprintf(w, "Instruction %s:\n", i)
	for val, marks := range fi.MarkedValues[i] {
		fmt.Fprintf(w, "   %s = %s marked by ", val.Name(), val)
		for mark := range marks {
			fmt.Fprintf(w, " <%s> ", &mark)
		}
		fmt.Fprintf(w, "\n")
	}
}

// HasMarkAt returns true if the value v has an abstract state at instruction i, and this abstract state contains the
// mark s.
func (fi *FlowInformation) HasMarkAt(i ssa.Instruction, v ssa.Value, s Mark) bool {
	marks, ok := fi.MarkedValues[i][v]
	return ok && marks[s]
}

// AddMark adds a mark to the tracking info structure and returns a boolean
// if new information has been inserted.
func (fi *FlowInformation) AddMark(i ssa.Instruction, v ssa.Value, s Mark) bool {

	if vMarks, ok := fi.MarkedValues[i][v]; ok {
		if vMarks[s] {
			return false
		} else {
			vMarks[s] = true
			return true
		}
	} else {
		fi.MarkedValues[i][v] = map[Mark]bool{s: true}
		return true
	}
}

func (fi *FlowInformation) SetLoc(mark Mark, instr ssa.Instruction) {
	if fi.LocSet[mark] == nil {
		fi.LocSet[mark] = map[ssa.Instruction]bool{}
	}
	fi.LocSet[mark][instr] = true
}
