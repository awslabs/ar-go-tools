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

package structinit

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// InvalidWriteReport contains the information we serialize about an invalid write.
//
// This gets written to a report file (usually json).
type InvalidWriteReport struct {
	StructField string
	GotValue    string
	WantValue   string
	Position    string
}

func (ir InvalidWriteReport) String() string {
	return fmt.Sprintf("found invalid write to struct field %s (want %s, got %s) at %s\n",
		ir.StructField, ir.WantValue, ir.GotValue, ir.Position)
}

func newInvalidWriteReport(write writeToField, namedType *types.Named, pos token.Position) InvalidWriteReport {
	return InvalidWriteReport{
		StructField: fmt.Sprintf("%s.%s", namedType.String(), write.fieldType.Name()),
		GotValue:    write.write.Got.String(),
		WantValue:   write.write.Want.String(),
		Position:    pos.String(),
	}
}

// IncompleteInitReport contains the information we serialize about an incomplete initialization.
//
// This gets written to a report file (usually json).
type IncompleteInitReport struct {
	Struct              string
	InvalidZeroedFields []string
	Position            string
}

func (ir IncompleteInitReport) String() string {
	return fmt.Sprintf("found incomplete initialization of struct %s with invalid zeroed fields %s at %s",
		ir.Struct, strings.Join(ir.InvalidZeroedFields, ","), ir.Position)
}

func newIncompleteInitReport(i IncompleteInit) IncompleteInitReport {
	return IncompleteInitReport{
		Struct:              i.Struct.String(),
		InvalidZeroedFields: i.InvalidZeroedFields,
		Position:            i.Pos.String(),
	}
}

// FormattedReport writes res to a string and returns true if the analysis should fail.
func FormattedReport(res AnalysisResult) (string, bool) {
	failed := false

	w := &strings.Builder{}
	w.WriteString("\nstruct-init analysis results:\n")
	w.WriteString("-----------------------------\n")
	for structName, info := range res.InitInfos {
		w.WriteString(fmt.Sprintf("initialization information for %v:\n", formatutil.Bold(structName)))
		if len(info.IncompleteInits) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("no incomplete initializations found")))
		}
		for _, alloc := range info.IncompleteInits {
			w.WriteString(fmt.Sprintf("\t%s: %v at %v\n", formatutil.Red("incomplete initialization"), alloc.Alloc, alloc.Pos))
			failed = true
		}

		for field, writes := range info.InvalidWrites {
			s := formatutil.Red("invalid writes")
			if len(writes) == 0 {
				s = formatutil.Green("no invalid writes")
			}
			w.WriteString(fmt.Sprintf("\t%s to field %v\n", s, field.Name()))
			for _, write := range writes {
				w.WriteString(fmt.Sprintf("\t\t%v (got %v, want %v) at %v\n", write.Instr, write.Got, write.Want, write.Pos))
				failed = true
			}
		}

		if len(info.BadReinits) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("all must-reinit constraints satisfied")))
		} else {
			w.WriteString(fmt.Sprintf("\t%s\n", formatutil.Red("missing reinitializations (must-reinit not satisfied):")))
		}
		for _, badReinit := range info.BadReinits {
			w.WriteString(fmt.Sprintf("\t   after call %s at %v\n", badReinit.Call.String(), badReinit.Pos))
			failed = true
		}
	}

	return w.String(), failed
}
