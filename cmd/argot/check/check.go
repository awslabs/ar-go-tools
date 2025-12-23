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

package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/check"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

// Usage for CLI
var usage string
var methods = []check.Method{check.Types, check.Immutability, check.All, check.Naive}

func init() {
	usage = fmt.Sprintf(`Check the soundness of the data flow summaries in a summary file.
See the "Dataflow Specifications" section in the taint analysis documentation
for information on how to write the summary file.

Usage:
  argot check [options] --summary <summary file path> --via <method> <package path(s)>

Where:
  <method> is one of %s`,
		methodsString())
}

// Flags represents the parsed flags for the taint analysis.
type Flags struct {
	tools.CommonFlags
	via check.Method
	log int
}

// NewFlags returns the parsed flags for the data flow summary checking analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags(config.CheckTool)
	via := flags.FlagSet.String("via", "all", "how to perform the check")
	level := flags.FlagSet.Int("log", 3, "log level (int)")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command check with args %v: %v", args, err)
	}

	if via == nil || !slices.Contains(methods, check.Method(*via)) {
		return Flags{}, fmt.Errorf("incorrect checking method: want one of %s", methodsString())
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
			Tag:        *flags.Tag,
			Targets:    *flags.Targets,
			Platform:   *flags.Platform,
			Out:        *flags.Out,
		},
		via: check.Method(*via),
		log: *level,
	}, nil
}

// Run runs the data flow summary checking analysis.
func Run(flags Flags) error {
	cfg, checkErr := tools.LoadConfig(flags.CommonFlags, true)
	if checkErr != nil {
		return fmt.Errorf("failed to load config: %v", checkErr)
	}
	cfg.DataflowProblems.SummarizeOnDemand = true
	cfg.LogLevel = flags.log
	cfg.Options.UnsafeMaxDepth = -1
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Info(formatutil.Faint("Argot check tool - " + analysis.Version))
	if len(cfg.UserSpecs) == 0 {
		tmpLogger.Infof("no user specs provided, nothing to do!")
		return nil
	}
	tmpLogger.Infof("Checking method: %s", flags.via)

	parsedSummaries := make([]summaries.FrontendDataflowSummary, 0)
	for _, specFile := range cfg.DataflowProblems.UserSpecs {
		userSummaries, checkErr := summaries.ParseSummariesFile(specFile)
		if checkErr != nil {
			return fmt.Errorf("failed to parse user specs file %s: %v", cfg.DataflowProblems.UserSpecs, checkErr)
		}
		parsedSummaries = append(parsedSummaries, userSummaries...)
	}

	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.FlagSet.Args(),
		Tag:         flags.Tag,
		Targets:     flags.Targets,
		Platform:    flags.Platform,
		Tool:        config.TaintTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get targets: %v", err)
	}

	for targetName, target := range actualTargets {
		targetErr := runTarget(cfg, targetName, target, parsedSummaries, flags)
		if targetErr != nil {
			tmpLogger.Errorf("failed to check soundness of summaries in target %s: %s", targetName, targetErr)
		}
	}
	return nil
}

func runTarget(
	cfg *config.Config,
	targetName string,
	targetInfo config.TargetInfo,
	parsedSummaries []summaries.FrontendDataflowSummary,
	flags Flags,
) error {
	var err error
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		Platform:      targetInfo.Platform,
		ApplyRewrites: true,
	}
	// Starting the analysis
	c := config.NewState(cfg, targetName, targetInfo.Patterns, loadOptions)
	c.Logger.PushContext(formatutil.Faint(targetName))
	defer c.Logger.PopContext()
	c.Logger.Infof("Dataflow checks for target \"%s\" = %v", targetName, targetInfo.Patterns)
	var actual result.Result[config.State]
	if targetInfo.UseProgramTransforms && len(targetInfo.ReflectValueCallInstances) >= 1 {
		c.Logger.Infof("Reflect value call instances specified. Tool supports only 1 for now, will use the first.")
		// TODO: handle more rewrites later
		actual = statefulrewrite.StatefulRewritesOverlayTransform(c,
			statefulrewrite.StatefulRewritesOverlayTransformSpec{ReflectValueCallInstanceCid: targetInfo.ReflectValueCallInstances[0]})
	} else {
		actual = result.Ok(c)
	}

	df, err := result.Bind(
		result.Bind(
			result.Bind(
				actual,
				loadprogram.NewState),
			ptr.NewState),
		dataflow.NewState).Value()
	specs := getScanningSpecs(df, targetName)
	if err != nil {
		return fmt.Errorf("failed to initialize dataflow state: %s", err)
	}

	// Create context with timeout from config
	ctx := context.Background()
	if timeout := df.Config.DataflowProblems.IntraTimeoutMs; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
	}

	results, checkErr := checkSummaries(ctx, df, parsedSummaries, flags.via, specs)
	// write the report before exiting, even if there was an error in checking summaries
	if err := report(cfg, results); err != nil {
		return err
	}
	if checkErr != nil {
		return checkErr
	}
	return nil
}

func report(cfg *config.Config, results []check.SoundnessResult) error {
	if cfg.ReportsDir != "" {
		reportFile, err := os.Create(filepath.Join(cfg.ReportsDir, "check-report.json"))
		if err != nil {
			return fmt.Errorf("failed to create report file: %v", err)
		}
		enc := json.NewEncoder(reportFile)
		enc.SetEscapeHTML(false) // don't escape characters like "<"
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("failed to marshal report to json: %v", err)
		}
	}
	return nil
}

func checkSummaries(
	ctx context.Context, ds *dataflow.State, parsedSummaries []summaries.FrontendDataflowSummary,
	via check.Method,
	specs []dataflow.ScanningSpec,
) ([]check.SoundnessResult, error) {
	sr := check.NewState(ds)
	s := sr.Unwrap()

	logger := s.Logger
	var errs []error
	logger.Info("Summaries to check:\n")
	for _, summary := range parsedSummaries {
		logger.Infof("\t%s\n", summary.Name())
	}

	results := make([]check.SoundnessResult, 0, len(parsedSummaries))
	for _, summary := range parsedSummaries {
		errs, results = checkOneSummaryWrapper(ctx, specs, summary, via, s, errs, results)
	}

	return results, errors.Join(errs...)
}

func checkOneSummaryWrapper(
	ctx context.Context,
	specs []dataflow.ScanningSpec,
	summary summaries.FrontendDataflowSummary,
	via check.Method,
	s *check.State,
	errs []error,
	results []check.SoundnessResult,
) ([]error, []check.SoundnessResult) {
	targetFunctionName := summary.Name()
	s.Logger.PushContext(formatutil.Faint(targetFunctionName))
	defer s.Logger.PopContext()
	s.Logger.Infof("Checking summary via %v...", via)
	soundness, err, foundFunc := check.CheckSummary(ctx, s, summary, specs)
	if !foundFunc {
		s.Logger.Warnf("Cannot find function %s, so summary will not be used in target (nothing to do).",
			summary.Name())
		return errs, results
	}
	if err != nil {
		// continue checking the rest of the summaries but return all the errors when finished
		s.Logger.Errorf("failed to check the summary of function %s in %v seconds: %v",
			targetFunctionName, soundness.Time.Seconds(), err)
		errs = append(errs, err)
		return errs, results
	}
	s.Logger.Infof("Result:\n%s\n", soundness.PrettyString())
	results = append(results, soundness)
	return errs, results
}

func methodsString() string {
	var res []string
	for _, m := range methods {
		res = append(res, string(m))
	}
	return strings.Join(res, ", ")
}

// getScanningSpecs returns the scanning specifications for the given configuration and target
func getScanningSpecs(state *dataflow.State, target string) []dataflow.ScanningSpec {
	if state == nil {
		return []dataflow.ScanningSpec{}
	}
	scanningSpecs := []dataflow.ScanningSpec{}
	for _, spec := range state.Config.DataflowProblems.TaintTrackingProblems {
		if funcutil.Exists(spec.Targets, func(s string) bool { return s == target }) {
			sc := dataflow.ScanningSpec{
				// The entry points are specific to each taint tracking problem (unlike in the intra-procedural pass)
				IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
					return dataflow.IsNodeOfInterest(state, node)
				},
				MarkCallArgsLikeCall: spec.SourceTaintsArgs,
			}
			scanningSpecs = append(scanningSpecs, sc)
		}
	}
	// Default scanning spec
	return scanningSpecs
}
