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
	log         int
}

// NewFlags returns the parsed flags for the data flow summary checking analysis with args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags(config.CheckTool)
	summaryPath := flags.FlagSet.String("summary", "", "path to data flow summary file")
	via := flags.FlagSet.String("via", "all", "how to perform the check")
	level := flags.FlagSet.Int("log", 3, "log level (int)")
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
		log:         *level,
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
	tmpLogger.Infof("Checking method: %s", flags.via)

	parsedSummaries, checkErr := summaries.ParseSummariesFile(flags.summaryPath)
	if checkErr != nil {
		return fmt.Errorf("failed to parse summaries file %s: %v", flags.summaryPath, checkErr)
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
	df, checkErr := result.Bind(ptrState, dataflow.NewState).Value()
	if checkErr != nil {
		return fmt.Errorf("failed to initialize dataflow state: %s", checkErr)
	}

	// Create context with timeout from config
	ctx := context.Background()
	if timeout := df.Config.DataflowProblems.IntraTimeoutMs; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
	}

	results, checkErr := checkSummaries(ctx, df, parsedSummaries, flags.via)
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
		targetName := summary.Name()
		logger.PushContext(formatutil.Faint(targetName))
		logger.Infof("Checking summary via %v...", via)
		soundness, err := check.CheckSummary(ctx, s, summary)
		if err != nil {
			// continue checking the rest of the summaries but return all the errors when finished
			logger.Errorf("failed to check the summary of function %s in %v seconds: %v", targetName, soundness.Time.Seconds(), err)
			errs = append(errs, err)
			continue
		}
		logger.Infof("Checked soundness of summary for function %s in %v seconds:\n", targetName, soundness.Time.Seconds())
		if soundness.IsSound {
			logger.Infof("Sound!")
		} else {
			// TODO proper soundness report
			logger.Errorf("Unsound!")
		}
		logger.Info("Unproven flows:")
		for _, flow := range soundness.BadFlows {
			logger.Infof("\t%s\n", flow)
		}

		results = append(results, soundness)
		logger.PopContext()
	}

	return results, errors.Join(errs...)
}

func methodsString() string {
	var res []string
	for _, m := range methods {
		res = append(res, string(m))
	}
	return strings.Join(res, ", ")
}
