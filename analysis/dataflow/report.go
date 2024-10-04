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
	"go/token"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

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

type unsoundFeaturesMap struct {
	Recovers      map[token.Position]bool
	UnsafeUsages  map[token.Position]string
	ReflectUsages map[token.Position]string
}

// reportUnsoundFeatures logs warning messages when unsound features are used in a function. Those include:
//
// - call to recover builtin
//
// - unsafe
//
// - reflect
//
// Usages of those features are logged at WARN level with the position of where the feature is used.
func reportUnsoundFeatures(state *AnalyzerState, f *ssa.Function) {
	unsoundFeatures := FindUnsoundFeatures(f)
	if len(unsoundFeatures.Recovers) > 0 ||
		len(unsoundFeatures.UnsafeUsages) > 0 ||
		len(unsoundFeatures.ReflectUsages) > 0 {
		msg := fmt.Sprintf("Function %s is using features that may make the analysis unsound.\n", f.String())

		if len(unsoundFeatures.Recovers) > 0 {
			msg += "    Using recover at position:\n"
		}
		for pos := range unsoundFeatures.Recovers {
			msg += "\t  " + pos.String() + "\n"
		}

		if len(unsoundFeatures.UnsafeUsages) > 0 {
			msg += "    Usages of unsafe:\n"
		}

		for pos, usageMsg := range unsoundFeatures.UnsafeUsages {
			msg += "      At " + pos.String() + " : " + usageMsg + "\n"
		}

		if len(unsoundFeatures.ReflectUsages) > 0 {
			msg += "    Usages of reflection:\n"
		}

		for pos, usageMsg := range unsoundFeatures.ReflectUsages {
			msg += "      At " + pos.String() + " : " + usageMsg + "\n"
		}
		msg += "    Adding a predefined summary might help avoid soundness issues.\n"

		state.Logger.Warnf(msg)
	}
}
func FindUnsoundFeatures(f *ssa.Function) unsoundFeaturesMap {
	unsafeUsages := map[token.Position]string{}
	recovers := map[token.Position]bool{}
	reflectUsages := map[token.Position]string{}
	lang.IterateInstructions(f, func(index int, instrI ssa.Instruction) {
		iPos := instrI.Parent().Prog.Fset.Position(instrI.Pos())
		switch instr := instrI.(type) {
		case ssa.CallInstruction:
			callCommon := instr.Common()
			if callCommon.Value == nil {
				return
			}
			if callCommon.Value.Name() == "recover" {
				recovers[iPos] = true
				return
			}
			if callCommon.IsInvoke() {
				// Only warn for implementations.
				return
			}
			typStr := callCommon.Value.Type().String()
			if strings.Contains(typStr, "unsafe") {
				unsafeUsages[iPos] = fmt.Sprintf("Calling %s from unsafe package.", callCommon.Value.Name())
				return
			}
			if strings.Contains(typStr, "reflect") {
				reflectUsages[iPos] = fmt.Sprintf("Calling %s from reflect package.", callCommon.Value.Name())
				return
			}

		case *ssa.Alloc:
			typ := instr.Type().Underlying()
			if strings.HasPrefix(typ.String(), "unsafe") {
				unsafeUsages[iPos] = fmt.Sprintf("Allocating object of type %s", typ.String())
				return
			}
			if strings.HasPrefix(typ.String(), "reflect") {
				reflectUsages[iPos] = fmt.Sprintf("Allocating object of type %s", typ.String())
				return
			}
		case *ssa.Convert:
			typStr := instr.Type().String()
			if strings.Contains(typStr, "unsafe") {
				unsafeUsages[iPos] = "Converting data to an unsafe pointer."
			}
		}
	})
	return unsoundFeaturesMap{recovers, unsafeUsages, reflectUsages}
}
