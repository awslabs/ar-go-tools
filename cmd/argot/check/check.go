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
	"fmt"
	"slices"
	"strings"

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
	summaryPath string
	via         check.Method
}

// NewFlags returns the parsed flags for the data flow summary checking analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags(config.CheckTool)
	summaryPath := flags.FlagSet.String("summary", "", "path to data flow summary file")
	via := flags.FlagSet.String("via", "all", "how to perform the check")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command check with args %v: %v", args, err)
	}
	if summaryPath == nil || *summaryPath == "" {
		return Flags{}, fmt.Errorf("must specify a data flow summary file")
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
		summaryPath: *summaryPath,
		via:         check.Method(*via),
	}, nil
}

// Run runs the data flow summary checking analysis.
func Run(flags Flags) error {
	cfg := config.NewDefault()
	cfg.DataflowProblems.SummarizeOnDemand = true
	cfg.LogLevel = int(config.InfoLevel)
	cfg.Options.UnsafeMaxDepth = -1
	tmpLogger := config.NewLogGroup(cfg)
	tmpLogger.Info(formatutil.Faint("Argot check tool - " + analysis.Version))
	tmpLogger.Infof("Checking method: %s", flags.via)

	parsedSummaries, err := summaries.ParseSummariesFile(flags.summaryPath)
	if err != nil {
		return fmt.Errorf("failed to parse summaries file %s: %v", flags.summaryPath, err)
	}

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		Platform:      flags.Platform,
		ApplyRewrites: false,
	}
	c := config.NewState(cfg, flags.summaryPath, flags.FlagSet.Args(), loadOptions)
	ptrState := result.Bind(loadprogram.NewState(c), ptr.NewState)
	df, err := result.Bind(ptrState, dataflow.NewState).Value()
	if err != nil {
		return fmt.Errorf("failed to initialize dataflow state: %s", err)
	}
	if err := checkSummaries(df, parsedSummaries, flags.via); err != nil {
		return fmt.Errorf("failed to check summaries: %v", err)
	}

	return nil
}

func checkSummaries(s *dataflow.State, parsedSummaries []summaries.FrontendDataflowSummary, via check.Method) error {
	check.InitializeState(s)

	logger := s.Logger
	for _, summary := range parsedSummaries {
		targetName := summary.Name()
		logger.PushContext(formatutil.Faint(targetName))
		logger.Infof("Checking summary...")
		soundness, err := check.CheckSummary(s, summary, via)
		if err != nil {
			return fmt.Errorf("failed to check the summary of function %s: %v", targetName, err)
		}
		logger.Infof("Summary for function %s:\n", targetName)
		logger.Infof("\t%s\n", soundness.Got)
		logger.PopContext()
	}

	return nil
}

func methodsString() string {
	var res []string
	for _, m := range methods {
		res = append(res, string(m))
	}
	return strings.Join(res, ", ")
}
