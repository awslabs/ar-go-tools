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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// FlowInformation contains the dataflow information necessary for the analysis and function summary building.
type FlowInformation struct {
	// Function is the function being analyzed
	Function *ssa.Function

	// user provided configuration identifying specific dataflow nodes to track and other settings (e.g. verbosity)
	Config *config.Config

	Marks map[Mark]*Mark

	// MarkedValues maps instructions to abstract states, i.e. a map from values to their abstract Value, which is a
	// set of marks
	MarkedValues map[ssa.Instruction]map[ssa.Value]abstractValue

	// LocSet is a map from marks to the locations associated to it. A location is associated to a mark when it
	// is used to propagate the mark during the monotone analysis. This is meant to be used by other analyses, and
	// does not contain user-interpretable information.
	LocSet map[*Mark]map[ssa.Instruction]bool
}

// NewFlowInfo returns a new FlowInformation with all maps initialized.
func NewFlowInfo(cfg *config.Config, f *ssa.Function) *FlowInformation {
	return &FlowInformation{
		Function:     f,
		Config:       cfg,
		Marks:        make(map[Mark]*Mark),
		MarkedValues: make(map[ssa.Instruction]map[ssa.Value]abstractValue),
		LocSet:       make(map[*Mark]map[ssa.Instruction]bool),
	}
}

func (fi *FlowInformation) GetNewMark(node ssa.Node, typ MarkType, qualifier ssa.Value, index int) *Mark {
	m := NewMark(node, typ, qualifier, index)
	if m0, ok := fi.Marks[m]; ok {
		return m0
	} else {
		fi.Marks[m] = &m
		return &m
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

// ShowAt pretty-prints the abstract state of the analysis at instruction i. A line is printed for every SSA Value with
// an abstract Value (a set of marks).
func (fi *FlowInformation) ShowAt(w io.Writer, i ssa.Instruction) {
	fmt.Fprintf(w, "Instruction %s:\n", i)
	for _, a := range fi.MarkedValues[i] {
		a.Show(w)
	}
}

// HasMarkAt returns true if the Value v has an abstract state at instruction i, and this abstract state contains the
// mark s.
func (fi *FlowInformation) HasMarkAt(i ssa.Instruction, v ssa.Value, path string, s *Mark) bool {
	marks, ok := fi.MarkedValues[i][v]
	return ok && marks.HasMarkAt(path, s)
}

// AddMark adds a mark to the tracking info structure and returns true if new information has been inserted.
// If false, then "fi" has not changed.
// In both cases, "fi" will have the mark "s" on ssa value "value" with "path" at instruction "i".
func (fi *FlowInformation) AddMark(i ssa.Instruction, value ssa.Value, path string, s *Mark) bool {
	if abstractState, ok := fi.MarkedValues[i][value]; ok {
		if abstractState.HasMarkAt(path, s) {
			return false
		} else {
			abstractState.add(path, s)
			return true
		}
	} else {
		as := newAbstractValue(value)
		as.add(path, s)
		fi.MarkedValues[i][value] = as
		return true
	}
}

func (fi *FlowInformation) SetLoc(mark *Mark, instr ssa.Instruction) {
	if fi.LocSet[mark] == nil {
		fi.LocSet[mark] = map[ssa.Instruction]bool{}
	}
	fi.LocSet[mark][instr] = true
}
