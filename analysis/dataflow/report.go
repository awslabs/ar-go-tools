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
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

func (s *AnalyzerState) reportNoCallee(instr ssa.CallInstruction) {
	pos := s.Program.Fset.Position(instr.Pos())

	if s.Config.ReportNoCalleeSites {
		f, err := os.OpenFile(s.Config.ReportNoCalleeFile(), os.O_APPEND, 0644)
		if err == nil {
			s.Logger.Errorf("Could not open %q\n", s.Config.ReportNoCalleeFile())
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\"%s\", %s", formatutil.SanitizeRepr(instr), pos))
	}

	s.Logger.Warnf("No callee found for %s.\n", formatutil.SanitizeRepr(instr))
	s.Logger.Warnf("Location: %s.\n", pos)
	if instr.Value() != nil {
		s.Logger.Warnf("Value: %s\n", formatutil.SanitizeRepr(instr.Value()))
		s.Logger.Warnf("Type: %s\n", formatutil.SanitizeRepr(instr.Value().Type()))
	} else {
		s.Logger.Warnf("Type: %s\n", formatutil.SanitizeRepr(instr.Common().Value.Type()))
	}

	s.Logger.Warnf("Method: %s\n", formatutil.SanitizeRepr(instr.Common().Method))
}

// ReportMissingOrNotConstructedSummary prints a missing summary message to the cache's logger.
func (s *AnalyzerState) ReportMissingOrNotConstructedSummary(callSite *CallNode) {
	if !s.Config.Verbose() {
		return
	}

	var typeString string
	if callSite.Callee() == nil {
		typeString = fmt.Sprintf("nil callee (in %s)",
			lang.SafeFunctionPos(callSite.Graph().Parent).ValueOr(lang.DummyPos))
	} else {
		typeString = formatutil.SanitizeRepr(callSite.Callee().Type())
	}
	if callSite.CalleeSummary == nil {
		s.Logger.Debugf(formatutil.Red(fmt.Sprintf("| %q has not been summarized (call %q).",
			callSite.String(), typeString)))
	} else if !callSite.CalleeSummary.Constructed {
		s.Logger.Debugf(formatutil.Red(fmt.Sprintf("| %q has not been constructed (call %q).",
			callSite.String(), typeString)))
	}
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		s.Logger.Debugf(fmt.Sprintf("| Please add %q to summaries", callSite.Callee().String()))

		pos := callSite.Position(s)
		if pos != lang.DummyPos {
			s.Logger.Debugf("|_ See call site: %s", pos)
		} else {
			opos := lang.SafeFunctionPos(callSite.Graph().Parent)
			s.Logger.Debugf("|_ See call site in %s", opos.ValueOr(lang.DummyPos))
		}

		methodFunc := callSite.CallSite().Common().Method
		if methodFunc != nil {
			methodKey := callSite.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
			s.Logger.Debugf("| Or add %s to dataflow contracts", formatutil.Sanitize(methodKey))
		}
	}
}

// ReportMissingClosureNode prints a missing closure node summary message to the cache's logger.
func (s *AnalyzerState) ReportMissingClosureNode(closureNode *ClosureNode) {
	if !s.Config.Verbose() {
		return
	}

	var instrStr string
	if closureNode.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = closureNode.Instr().String()
	}
	s.Logger.Debugf(formatutil.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		closureNode.String(), formatutil.Sanitize(instrStr))))
	if closureNode.Instr() != nil {
		s.Logger.Debugf("| Please add closure %s to summaries",
			formatutil.SanitizeRepr(closureNode.Instr().Fn))
		s.Logger.Debugf("|_ See closure: %s", closureNode.Position(s))
	}
}

// ReportSummaryNotConstructed prints a warning message to the cache's logger.
func (s *AnalyzerState) ReportSummaryNotConstructed(callSite *CallNode) {
	if !s.Config.Verbose() {
		return
	}

	s.Logger.Debugf("| %s: summary has not been built for %s.",
		formatutil.Yellow("WARNING"),
		formatutil.Yellow(callSite.Graph().Parent.Name()))
	pos := callSite.Position(s)
	if pos != lang.DummyPos {
		s.Logger.Debugf(fmt.Sprintf("|_ See call site: %s", pos))
	} else {
		opos := lang.SafeFunctionPos(callSite.Graph().Parent)
		s.Logger.Debugf(fmt.Sprintf("|_ See call site in %s", opos.ValueOr(lang.DummyPos)))
	}

	if callSite.CallSite() != nil {
		methodKey := lang.InstrMethodKey(callSite.CallSite())
		if methodKey.IsSome() {
			s.Logger.Debugf(fmt.Sprintf("| Or add %s to dataflow contracts",
				formatutil.Sanitize(methodKey.ValueOr("?"))))
		}
	}
}

func reportFlowInformation(state *AnalyzerState, fi *FlowInformation) {
	if fi.Function == nil {
		return
	}

	lang.IterateInstructions(fi.Function, func(_ int, i ssa.Instruction) {
		state.Logger.Infof("• instruction %s @ %s:\n", formatutil.Cyan(i.String()), state.Program.Fset.Position(i.Pos()))
		// sort and print Value -> marks
		var mVals []ssa.Value
		iId := fi.InstrId[i]
		index := iId * fi.NumValues
		for _, val := range fi.MarkedValues[index : index+fi.NumValues] {
			if val != nil {
				mVals = append(mVals, val.value)
			}
		}
		slices.SortFunc(mVals, func(a, b ssa.Value) int {
			var s1, s2 string
			setStr(a, &s1)
			setStr(a, &s2)
			return strings.Compare(s1, s2)
		})
		for _, val := range mVals {
			marks := fi.MarkedValues[index+fi.ValueId[val]]
			var x, vStr, vName string
			setStr(val, &vStr)
			setName(val, &vName)
			_, isFunc := val.(*ssa.Function)
			if isFunc {
				x = "fun " + vName
			} else if vStr != vName {
				x = vName + "=" + vStr
			}
			for path, markSet := range marks.PathMappings {
				var markStrings []string
				for mark := range markSet {
					markStrings = append(markStrings, formatutil.Red(mark.String()))
				}
				state.Logger.Infof(
					"   %-30s %-10s marked by %s\n",
					formatutil.Magenta(x), formatutil.Yellow(path),
					strings.Join(markStrings, " & "))
			}
		}
	})
}

func setStr(a ssa.Value, s *string) {
	defer func() {
		if r := recover(); r != nil {
			*s = ""
		}
	}()
	*s = a.String()
}

func setName(a ssa.Value, s *string) {
	// Fencing off the insane error with some String() calls on ssa values
	defer func() {
		if r := recover(); r != nil {
			*s = ""
		}
	}()
	*s = a.Name()
}
