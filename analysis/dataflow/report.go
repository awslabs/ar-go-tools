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

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

func (s *AnalyzerState) reportNoCallee(instr ssa.CallInstruction) {
	pos := s.Program.Fset.Position(instr.Pos())

	if s.Config.ReportNoCalleeSites {
		f, err := os.OpenFile(s.Config.ReportNoCalleeFile(), os.O_APPEND, 0644)
		if err == nil {
			s.Logger.Errorf("Could not open %s\n", s.Config.ReportNoCalleeFile())
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\"%s\", %s", instr.String(), pos))
	}

	s.Logger.Warnf("No callee found for %s.\n", instr.String())
	s.Logger.Warnf("Location: %s.\n", pos)
	if instr.Value() != nil {
		s.Logger.Warnf("Value: %s\n", instr.Value().String())
		s.Logger.Warnf("Type: %s\n", instr.Value().Type())
	} else {
		s.Logger.Warnf("Type: %s\n", instr.Common().Value.Type())
	}

	s.Logger.Warnf("Method: %s\n", instr.Common().Method)
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
		typeString = callSite.Callee().Type().String()
	}
	if callSite.CalleeSummary == nil {
		s.Logger.Debugf(formatutil.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
			callSite.String(), typeString)))
	} else if !callSite.CalleeSummary.Constructed {
		s.Logger.Debugf(formatutil.Red(fmt.Sprintf("| %s has not been constructed (call %s).",
			callSite.String(), typeString)))
	}
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		s.Logger.Debugf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))

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
			s.Logger.Debugf("| Or add %s to dataflow contracts", methodKey)
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
		closureNode.String(), instrStr)))
	if closureNode.Instr() != nil {
		s.Logger.Debugf("| Please add closure %s to summaries",
			closureNode.Instr().Fn.String())
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
			s.Logger.Debugf(fmt.Sprintf("| Or add %s to dataflow contracts", methodKey.ValueOr("?")))
		}
	}
}
