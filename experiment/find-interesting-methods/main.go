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

// find-interesting-methods is a standalone tool (part of the ar-go-tools module) that identifies
// "interesting" methods to summarize -- methods reached by taint propagation that cause
// state-space explosion or could not be soundly analyzed (see requirements.md).
//
// It has two subcommands:
//
//	find-interesting-methods produce --config /path/to/argot-config.yaml --out raw.json
//	find-interesting-methods consume --in raw.json --out interesting-methods.json
//
// produce runs the (expensive) taint analysis once and writes the raw per-function signals.
// consume re-runs the (cheap) classification/aggregation logic over that raw data, so
// post-processing changes (thresholds, interface aggregation) don't require re-running the
// analysis. consume's raw input is also useful on its own for writing up results.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: find-interesting-methods <produce|consume> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "produce":
		err = runProduce(os.Args[2:])
	case "consume":
		err = runConsume(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q: expected produce or consume\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runProduce runs the taint analysis against a repo's argot-config.yaml and writes the raw
// per-function signals recorded (RawData) to --out.
func runProduce(args []string) error {
	fs := flag.NewFlagSet("produce", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the repo's argot-config.yaml (required)")
	outPath := fs.String("out", "raw-interesting-functions.json", "path to write the raw signals JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}

	config.SetGlobalConfig(*configPath)
	cfg, err := config.LoadGlobal(nil)
	if err != nil {
		return fmt.Errorf("failed to load config file %s: %w", *configPath, err)
	}

	// unsafe-max-depth must be set (>0) for the max-calling-context-depth unsoundness signal to
	// ever fire (see analysis/config/config.go's ExceedsMaxDepth); auto-correct if unset.
	const autoUnsafeMaxDepth = 35
	if cfg.UnsafeMaxDepth <= 0 {
		fmt.Fprintf(os.Stderr, "unsafe-max-depth was %d in %s, overriding to %d so the "+
			"max-calling-context-depth signal can fire\n", cfg.UnsafeMaxDepth, *configPath, autoUnsafeMaxDepth)
		cfg.UnsafeMaxDepth = autoUnsafeMaxDepth
	}

	// dataflow-problems.user-specs must be empty: functions with an externally-provided summary
	// are IsPreSummarized and skip onDemandIntraProcedural entirely (see
	// analysis/taint/dataflow_visitor.go), so none of the state-space-explosion signals (timing,
	// NumValues, context-loss, interface-fanout) can ever be recorded for them.
	if len(cfg.DataflowProblems.UserSpecs) > 0 {
		fmt.Fprintf(os.Stderr, "dataflow-problems.user-specs was %v in %s, clearing it so every "+
			"function is on-demand analyzed instead of pre-summarized\n",
			cfg.DataflowProblems.UserSpecs, *configPath)
		cfg.DataflowProblems.UserSpecs = nil
	}

	targets, err := tools.GetTargets(cfg, tools.TargetReqs{Tool: config.TaintTool})
	if err != nil {
		return fmt.Errorf("failed to get targets: %w", err)
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets with taint-tracking problems found in %s", *configPath)
	}
	if len(targets) > 1 {
		names := make([]string, 0, len(targets))
		for name := range targets {
			names = append(names, name)
		}
		return fmt.Errorf("%s defines %d targets with taint-tracking problems (%v): "+
			"find-interesting-methods requires exactly one target per repo to keep results "+
			"unambiguous -- use a config with a single target, or filter to one via a dedicated "+
			"config", *configPath, len(targets), names)
	}

	// Exactly one target at this point (validated above); extract it.
	var targetName string
	var targetInfo config.TargetInfo
	for targetName, targetInfo = range targets {
		break
	}

	fmt.Fprintf(os.Stderr, "analyzing target %q...\n", targetName)
	interesting, analyzeErr := runTarget(cfg, targetName, targetInfo)
	if analyzeErr != nil {
		// A timeout or internal error stops the analysis early (see
		// analysis/taint/dataflow_visitor.go): the result is incomplete, but the signals
		// recorded before the stop are still written out, with the affected functions flagged.
		fmt.Fprintf(os.Stderr, "target %q: %v\n", targetName, analyzeErr)
	}

	var records []RawRecord
	for f, sig := range interesting {
		if f.Parent() != nil || f.Synthetic != "" {
			continue
		}
		reasons := interestingReasons(sig)
		if len(reasons) == 0 {
			continue
		}
		entries := classifyEntries(f, sig)
		records = append(records, NewRawRecord(f.String(), entries, reasons, sig))
	}
	if err := WriteRawData(*outPath, RawData{Records: records}); err != nil {
		return fmt.Errorf("failed to write %s: %w", *outPath, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d raw record(s) to %s\n", len(records), *outPath)
	return nil
}

// runTarget runs the taint analysis on a single target, returning the InterestingFunctions
// signals recorded.
func runTarget(cfg *config.Config, targetName string, targetInfo config.TargetInfo) (
	taint.InterestingFunctions, error) {
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.InstantiateGenerics,
		Platform:      targetInfo.Platform,
		ApplyRewrites: true,
	}
	c := config.NewState(cfg, targetName, targetInfo.Patterns, loadOptions)
	df, err := result.Bind(
		result.Bind(
			result.Bind(
				result.Ok(c),
				loadprogram.NewState),
			ptr.NewState),
		dataflow.NewState).Value()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize dataflow state: %w", err)
	}

	// SetInterestingFunctions on a per-target visitor happens inside taint.Analyze; the same map
	// is accumulated across all of the target's taint problems and returned in AnalysisResult.
	res, analyzeErr := taint.Analyze(context.Background(), df, taint.AnalysisReqs{})
	return res.InterestingFunctions, analyzeErr
}

// runConsume reads a RawData file produced by produce and writes the to_summarize.json-schema
// output (a bare array of MethodEntry) to --out: it just deduplicates the (already-decided)
// Entries across records, since the same interface method can be contributed by many concrete
// implementations.
func runConsume(args []string) error {
	fs := flag.NewFlagSet("consume", flag.ContinueOnError)
	inPath := fs.String("in", "", "path to the raw signals JSON file written by produce (required)")
	outPath := fs.String("out", "interesting-methods.json", "path to write the resulting JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		return fmt.Errorf("--in is required")
	}

	data, err := ReadRawData(*inPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", *inPath, err)
	}

	var timedOut []string
	seen := map[MethodEntry]bool{}
	var entries []MethodEntry
	for _, record := range data.Records {
		for _, u := range record.Unsoundness {
			if u == taint.UnsoundnessTimeout {
				timedOut = append(timedOut, record.FuncString)
			}
		}
		for _, entry := range record.Entries {
			if !seen[entry] {
				seen[entry] = true
				entries = append(entries, entry)
			}
		}
	}

	if err := WriteMethodEntries(*outPath, entries); err != nil {
		return fmt.Errorf("failed to write %s: %w", *outPath, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d interesting method(s) to %s\n", len(entries), *outPath)
	if len(timedOut) > 0 {
		fmt.Fprintf(os.Stderr, "%d function(s) timed out and need a manual ground-truth summary "+
			"before re-running produce (see %s)\n", len(timedOut), *outPath)
	}
	return nil
}
