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

package taint

import (
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// An AnalysisResult from the taint analysis contains the tainted flows in TaintFLows and the analyzer state at the
// end of the analysis in State. Optionally, an explicit inter-procedural graph is constructed.
type AnalysisResult struct {
	// TaintFlows contains all the data flows from the sources to the sinks detected during the analysis
	TaintFlows *Flows

	// State is the state at the end of the analysis, if you need to chain another analysis
	State *dataflow.State

	// Graph is the cross function dataflow graph built by the dataflow analysis. It contains the linked summaries of
	// each function appearing in the program and analyzed.
	Graph dataflow.InterProceduralFlowGraph

	// Errors contains a list of errors produced by the analysis. Errors may have been added at different steps of the
	// analysis.
	Errors []error
}

// AnalysisReqs provides constraints on the taint analysis to run.
type AnalysisReqs struct {
	// Tag is the tag to analyze, ignored if non-empty.
	Tag string
}

// Analyze runs the taint analysis on the provided state, which contains the program to analyze as well as the config
// defining the taint analysis problems.
// THe reqs arguments provides additional constraints on which problems to analyze.
func Analyze(state *dataflow.State, reqs AnalysisReqs) (AnalysisResult, error) {
	var err error
	// Number of working routines to use in parallel. TODO: make this an option?
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	preambleErr := AnalysisPreamble(state)
	if preambleErr != nil {
		return AnalysisResult{State: state}, preambleErr
	}
	// ** Second step **
	// The intra-procedural analysis is run on every function `f` such that `ignoreInFirstPass(f)` is
	// false. A dummy summary is inserted for every function that is not analyzed. If that dummy summary is needed
	// later in the inter-procedural analysis, then we [TODO: what do we do?].
	// The goal of this step is to build function summaries: a graph that represents how data flows through the
	// function being analyzed.

	// Only build summaries for non-stdlib functions here
	dataflow.RunIntraProceduralPass(state, numRoutines,
		dataflow.IntraAnalysisParams{
			ShouldBuildSummary: dataflow.ShouldBuildSummary,
			// For the intra-procedural pass, all source nodes of all problems are marked
			ShouldTrack: dataflow.IsNodeOfInterest,
		})

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source, for every taint tracking problem defined by the config and the annotations.

	// capture the annotation-defined problems
	tags := map[string]bool{}
	state.Annotations.Iter(func(a annotations.Annotation) {
		// scan the source annotations for all the tags, if there is no problem with that tag add it to the
		// config's TaintTrackingProblems
		if a.Kind == annotations.Source {
			for _, key := range a.Tags {
				if tagged := tags[key]; !tagged {
					if !funcutil.Exists(state.Config.TaintTrackingProblems, func(spec config.TaintSpec) bool {
						return spec.Tag == key
					}) {
						state.Config.TaintTrackingProblems = append(state.Config.TaintTrackingProblems,
							config.TaintSpec{Tag: key})
					}
					tags[key] = true
				}
			}
		}
	})

	taintFlows := NewFlows()

	for _, taintSpec := range state.Config.TaintTrackingProblems {
		// Check the tag must be analyzed
		if reqs.Tag != "" && taintSpec.Tag != reqs.Tag {
			state.Logger.Infof("Ignoring problem tagged %s since tag to analyze is provided.", taintSpec.Tag)
			continue
		}
		// Check the problem applies to the current target
		if !config.TargetIncludes(taintSpec.Targets, state.Target) {
			continue
		}
		// Number of alarms is problem specific, not global
		state.ResetAlarms()

		state.Logger.Infof("====================== NEW PROBLEM: %s =======================", taintSpec.Tag)
		// Set problem-specific options
		prevOptions := state.Config.AnalysisProblemOptions

		// Overriding options with problem-specific config
		if taintSpec.AnalysisProblemOptions != nil {
			config.OverrideWithAnalysisOptions(state.Logger, state.Config, taintSpec.AnalysisProblemOptions)
		}

		// Overriding options with annotations
		for optionName, optionValue := range state.Annotations.Configs[taintSpec.Tag] {
			_, errSetting := config.SetOption(state.Config, optionName, optionValue)
			if errSetting != nil {
				state.Logger.Warnf("ignoring option %s setting to %s in annotations because not a valid option",
					optionName, optionValue)
			} else {
				state.Logger.Infof("%s set to %s (using annotation).",
					optionName, optionValue)
			}
		}
		state.Logger.Debugf("Options: %+v", state.Config.Options)
		visitor := NewVisitor(&taintSpec)
		dataflow.RunInterProcedural(state, visitor, dataflow.ScanningSpec{
			// The entry points are specific to each taint tracking problem (unlike in the intra-procedural pass)
			IsEntryPointSsa:      func(node ssa.Node) bool { return dataflow.IsSourceNode(state, &taintSpec, node) },
			MarkCallArgsLikeCall: taintSpec.SourceTaintsArgs,
		})
		taintFlows.Merge(visitor.taints)
		// Restore global options
		state.Config.AnalysisProblemOptions = prevOptions
		state.Logger.Infof("Done analyzing %s", taintSpec.Tag)
	}

	// ** Fourth step **
	// Additional analyses are run after the taint analysis has completed. Those analyses check the soundness of the
	// result after the fact, and some other analyses can be used to prune false alarms.

	if state.Report.HasErrors() {
		err = errors.Join(state.Report.CheckError()...)
	}
	return AnalysisResult{State: state, Graph: *state.FlowGraph, TaintFlows: taintFlows}, err
}

// AnalysisPreamble groups different minor analyses that need to run before the intra-procedural step of the taint
// analysis.
func AnalysisPreamble(state *dataflow.State) error {
	// Add interface implementations as sinks
	populateConfigInterfaces(state)

	// Optional step: running the escape analysis
	if state.Config.UseEscapeAnalysis {
		state.Logger.Infof("Starting escape bottom-up analysis ...")
		start := time.Now()

		err := escape.InitializeEscapeAnalysisState(state)
		state.Logger.Infof("Escape bottom-up pass done (%.2f s).", time.Since(start).Seconds())

		if err != nil {
			return err
		}
	}
	return nil
}

// populateConfigInterfaces adds all the interface implementations for sinks to s.Config.TaintTrackingProblems.
func populateConfigInterfaces(s *dataflow.State) {
	newTaintSpecs := make([]config.TaintSpec, 0, len(s.Config.TaintTrackingProblems))
	for _, taintSpec := range s.Config.TaintTrackingProblems {
		for _, ci := range taintSpec.Sinks {
			interfaceToImpls, ok := findImpls(s, ci)
			if !ok {
				continue
			}

			for interfaceMethodName, impls := range interfaceToImpls {
				iid := interfaceMethodIdent(interfaceMethodName)
				s.Logger.Infof("Adding interface method to config sinks: %+v\n", iid)
				// add the interface method
				taintSpec.Sinks = append(taintSpec.Sinks, iid)
				for impl := range impls {
					fid := interfaceImplMethodIdent(impl)
					s.Logger.Infof("\tAdding interface implementation method to config sinks: %+v\n", fid)
					taintSpec.Sinks = append(taintSpec.Sinks, fid)
				}
			}
		}

		// newTaintSpecs is needed because taintSpec is a copy
		newTaintSpecs = append(newTaintSpecs, taintSpec)
	}

	s.Config.TaintTrackingProblems = newTaintSpecs
}

// interfaceMethodIdent returns the CodeIdentifier based on the interface method name.
func interfaceMethodIdent(interfaceMethodName string) config.CodeIdentifier {
	split := strings.Split(interfaceMethodName, ".")
	// should always be true
	if len(split) >= 3 {
		// e.g. github.com/repo/package.ReceiverType.Method
		//      ^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^
		//      package                 receiver     method
		return config.NewCodeIdentifier(config.CodeIdentifier{
			Package:  strings.Join(split[0:len(split)-2], "."),
			Receiver: split[len(split)-2],
			Method:   split[len(split)-1],
		})
	}

	return config.CodeIdentifier{}
}

// interfaceImplMethodIdent returns the CodeIdentifier for impl.
func interfaceImplMethodIdent(impl *ssa.Function) config.CodeIdentifier {
	// method receiver is the first parameter
	// should always be true
	if len(impl.Params) > 0 {
		receiver := impl.Params[0]
		recvStr := analysisutil.ReceiverStr(receiver.Type())
		return config.NewCodeIdentifier(config.CodeIdentifier{
			Package:  lang.PackageNameFromFunction(impl),
			Receiver: recvStr,
			Method:   impl.Name(),
		})
	}

	return config.CodeIdentifier{}
}

// findImpls returns a map of the interface method name for ci's interface with all the interface implementations' methods.
// TODO refactor to avoid string comparisons
func findImpls(s *dataflow.State, ci config.CodeIdentifier) (map[string]map[*ssa.Function]bool, bool) {
	if ci.Interface == "" {
		return nil, false
	}

	res := make(map[string]map[*ssa.Function]bool)
	found := false
	for interfaceName, impls := range s.ImplementationsByType {
		if strings.Contains(interfaceName, ci.FullMethodName()) {
			res[interfaceName] = make(map[*ssa.Function]bool)
			for impl := range impls {
				res[interfaceName][impl] = true
				found = true
			}
		}
	}

	return res, found
}
