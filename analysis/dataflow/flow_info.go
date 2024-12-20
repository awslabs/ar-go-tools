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

// IndexT is the type used to index values and instructions
type IndexT = uint32

// FlowInformation contains the dataflow information necessary for the analysis and function summary building.
type FlowInformation struct {
	// Function is the function being analyzed
	Function *ssa.Function

	// user provided configuration identifying specific dataflow nodes to track and other settings (e.g. verbosity)
	Config *config.Config

	// marks maps mark values to the pointer representing them
	marks map[Mark]*Mark

	// NumBlocks is the number of blocks in the function
	NumBlocks IndexT

	// NumValues is the number of values used in the function (values defined + used)
	NumValues IndexT

	// NumInstructions is the number of instructions in the function
	NumInstructions IndexT

	// FirstInstr is the first non-ignored instruction in the function
	FirstInstr ssa.Instruction

	// ValueID maps ssa.Value to value id
	ValueID map[ssa.Value]IndexT

	// InstrID maps ssa.Instruction to instruction id
	InstrID map[ssa.Instruction]IndexT

	// values maps value ids to ssa.Value
	values []ssa.Value

	// pathSensitivityFilter masks values that need to be handled in a field-sensitive manner
	pathSensitivityFilter []bool

	// MarkedValues maps instructions to abstract states, i.e. a map from values to their abstract Value, which is a
	// set of marks
	MarkedValues []*AbstractValue

	// LocSet is a map from marks to the locations associated to it. A location is associated to a mark when it
	// is used to propagate the mark during the monotone analysis. This is meant to be used by other analyses, and
	// does not contain user-interpretable information.
	LocSet map[*Mark]map[ssa.Instruction]bool
}

// NewFlowInfo returns a new FlowInformation with all maps initialized.
func NewFlowInfo(cfg *config.Config, f *ssa.Function) *FlowInformation {
	valueID := map[ssa.Value]IndexT{}
	numValues := IndexT(0)
	lang.IterateValues(f, func(_ int, v ssa.Value) {
		if v == nil {
			return
		}
		_, ok := valueID[v]
		if !ok {
			valueID[v] = numValues
			numValues++
		}
	})
	values := make([]ssa.Value, numValues)
	for v, x := range valueID {
		values[x] = v
	}

	numInstructions := IndexT(0)
	instrID := map[ssa.Instruction]IndexT{}
	var firstInstr ssa.Instruction
	lang.IterateInstructions(f, func(_ int, i ssa.Instruction) {
		if isInstrIgnored(i) {
			// we do not track debug ref in the analysis
			return
		}
		_, ok := instrID[i]
		if !ok {
			if firstInstr == nil {
				firstInstr = i
			}
			instrID[i] = numInstructions
			numInstructions++
		}
	})

	pathSensitivityFilter := make([]bool, numValues)
	pathSensitive := false
	if f != nil {
		pathSensitive = cfg.IsPathSensitiveFunc(f.String())
	}
	for i := range values {
		pathSensitivityFilter[i] = pathSensitive
	}

	return &FlowInformation{
		Function:              f,
		Config:                cfg,
		marks:                 make(map[Mark]*Mark),
		NumBlocks:             IndexT(len(f.Blocks)),
		NumValues:             numValues,
		NumInstructions:       numInstructions,
		ValueID:               valueID,
		InstrID:               instrID,
		FirstInstr:            firstInstr,
		values:                values,
		pathSensitivityFilter: pathSensitivityFilter,
		MarkedValues:          make([]*AbstractValue, numValues*numInstructions),
		LocSet:                make(map[*Mark]map[ssa.Instruction]bool, numValues),
	}
}

// GetPos returns the position of the abstract value at instruction i in the slice-based representation (the ValueID
// and InstrID map values and instructions to some ids, but a value in an instruction has a position in the
// MarkedValues slice that is calculated by (instruction id) * (number of instructions) + (value id)
// Returns the indexT (positive integer) and a boolean indicating whether the position exists.
func (fi *FlowInformation) GetPos(i ssa.Instruction, v ssa.Value) (IndexT, bool) {
	iID, ok := fi.InstrID[i]
	if !ok {
		return 0, false
	}
	vID, ok := fi.ValueID[v]
	if !ok {
		return 0, false
	}
	return iID*fi.NumValues + vID, true
}

// GetInstrPos returns the position of the instruction in the slice-based representations
// The instruction must be present in the array of InstrID. This is in general true if you have initialized the
// FlowInformation properly and you are working in the same function.
func (fi *FlowInformation) GetInstrPos(i ssa.Instruction) IndexT {
	return fi.InstrID[i] * fi.NumValues
}

// GetNewMark returns a pointer to the mark with the provided arguments. Internally checks whether the mark object
// representing this mark already exists.
func (fi *FlowInformation) GetNewMark(node ssa.Node, typ MarkType, qualifier ssa.Value, mi MarkIndex) *Mark {
	// Validate mark
	if typ == CallReturn {
		i, isCall := node.(*ssa.Call)
		if isCall && mi.Kind == ReturnedTupleIndex {
			ctyp := i.Common().Signature().Results()
			if ctyp != nil {
				if ctyp.Len() <= mi.Value {
					panic(fmt.Sprintf("Malformed constraint: a tuple %v but index %d out of bounds",
						typ, mi.Value))
				}
			}
		}
	}
	m := NewMark(node, typ, qualifier, mi, "")
	if m0, ok := fi.marks[m]; ok {
		return m0
	}
	fi.marks[m] = &m
	return &m
}

// GetNewLabelledMark returns a pointer to the labelled mark with the provided arguments. Internally checks whether
// the mark object representing this mark already exists.
func (fi *FlowInformation) GetNewLabelledMark(node ssa.Node, typ MarkType,
	qualifier ssa.Value, mi MarkIndex, label string) *Mark {
	m := NewMark(node, typ, qualifier, mi, label)
	if m0, ok := fi.marks[m]; ok {
		return m0
	}
	fi.marks[m] = &m
	return &m
}

// GetValueID returns the id of v if v in the FlowInformation and true, otherwise returns 0 and false if v is not
// tracked in the FLowInformation
func (fi *FlowInformation) GetValueID(v ssa.Value) (IndexT, bool) {
	vID, ok := fi.ValueID[v]
	if !ok {
		return 0, false
	}
	return vID, true
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
	iID := fi.GetInstrPos(i)
	for _, a := range fi.MarkedValues[iID : iID+fi.NumValues] {
		a.Show(w)
	}
}

// HasMarkAt returns true if the Value v has an abstract state at instruction i, and this abstract state contains the
// mark s.
func (fi *FlowInformation) HasMarkAt(i ssa.Instruction, v ssa.Value, path string, s *Mark) bool {
	pos, ok := fi.GetPos(i, v)
	if !ok {
		return false
	}
	marks := fi.MarkedValues[pos]
	return marks != nil && marks.HasMarkAt(path, s)
}

// AddMark adds a mark to the tracking info structure and returns true if new information has been inserted.
// If false, then "fi" has not changed.
// In both cases, "fi" will have the mark "s" on ssa value "value" with "path" at instruction "i".
func (fi *FlowInformation) AddMark(i ssa.Instruction, value ssa.Value,
	path string, s *Mark) bool {
	pos, ok := fi.GetPos(i, value)
	if !ok { // this is not a value in the function
		return false
	}
	if abstractState := fi.MarkedValues[pos]; abstractState != nil {
		if abstractState.HasMarkAt(path, s) {
			return false
		}
		abstractState.add(path, s)
		return true
	}
	as := NewAbstractValue(value, fi.pathSensitivityFilter[fi.ValueID[value]])
	as.add(path, s)
	fi.MarkedValues[pos] = as
	return true
}

// SetLoc sets locality information for a mark.
// In the current representation, this adds an instruction to the set of instructions associated to a specific mark.
func (fi *FlowInformation) SetLoc(mark *Mark, instr ssa.Instruction) {
	if fi.LocSet[mark] == nil {
		fi.LocSet[mark] = map[ssa.Instruction]bool{}
	}
	fi.LocSet[mark][instr] = true
}

// isInstrIgnored returns true is the instruction should be ignored in the analysis
func isInstrIgnored(i ssa.Instruction) bool {
	_, isDebugRef := i.(*ssa.DebugRef)
	return isDebugRef
}
