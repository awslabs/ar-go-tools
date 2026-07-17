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

// eval-checker is a standalone tool (part of the ar-go-tools module, so it always builds
// against the local analysis/summaries package) that turns check-report.json files produced by
// `argot check` (via run-check/run-constructive in run_experiment.py) into the
// {rq, repo, targets} JSON schema used by the paper's RQ1/RQ2/RQ3 tables.
//
// It has three subcommands, mirroring run_experiment.py's eval-checker-* commands:
//
//	eval-checker precision   --repo R --summaries FILE... --check-report FILE --constructive-report FILE --out FILE
//	eval-checker efficiency  --repo R --summaries FILE... --check-report FILE --constructive-report FILE --out FILE
//	eval-checker ablation    --repo R --summaries FILE... --check-report FILE --out FILE
//
// Grouping and flow-count logic is intentionally kept here (in Go) rather than in
// run_experiment.py, so that it can reuse analysis/summaries' ParseSummaryNode/DetailedSummary/
// UncoveredFlows directly instead of re-implementing summary-node comparison semantics in
// Python. The "excess flow" concept computed by "precision" is only meaningful because the RQ1
// ground-truth summaries (--summaries) are known-sound by construction (hand-curated) -- this
// assumption belongs here, in the experiment-evaluation tool, not in argot check's general
// -purpose report.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "precision":
		err = runPrecision(os.Args[2:])
	case "efficiency":
		err = runEfficiency(os.Args[2:])
	case "ablation":
		err = runAblation(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "eval-checker:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: eval-checker <precision|efficiency|ablation> [flags]")
}

// commonFlags are the flags shared by all three subcommands.
type commonFlags struct {
	repo        string
	summaries   multiFlag
	checkReport string
	out         string
}

// multiFlag allows -summaries to be repeated on the command line.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint(*m) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parseCommon(fs *flag.FlagSet, args []string, needConstructive bool) (commonFlags, string, error) {
	var f commonFlags
	var constructiveReport string
	fs.StringVar(&f.repo, "repo", "", "repo name (for the output's \"repo\" field)")
	fs.Var(&f.summaries, "summaries", "path to a ground-truth summaries YAML file (repeatable)")
	fs.StringVar(&f.checkReport, "check-report", "", "path to check-report.json")
	if needConstructive {
		fs.StringVar(&constructiveReport, "constructive-report", "", "path to constructive check-report.json")
	}
	fs.StringVar(&f.out, "out", "", "path to write the output JSON to")
	if err := fs.Parse(args); err != nil {
		return f, "", err
	}
	if f.repo == "" || len(f.summaries) == 0 || f.checkReport == "" || f.out == "" {
		return f, "", fmt.Errorf("missing required flag(s); need -repo, -summaries, -check-report, -out")
	}
	return f, constructiveReport, nil
}

// evalOutput is the {rq, repo, targets} schema shared by all three eval-checker-* commands.
type evalOutput struct {
	RQ      string   `json:"rq"`
	Repo    string   `json:"repo"`
	Targets []target `json:"targets"`
}

type target struct {
	SummaryName string   `json:"summary_name"`
	Kind        string   `json:"kind"`
	Results     []result `json:"results"`
}

// result is a single method/implementation's row. Fields are omitted (via omitempty) rather
// than zero-valued when not applicable to a given rq, matching run_experiment.py's previous
// behavior of deleting inapplicable keys.
type result struct {
	Name                        string   `json:"name"`
	CheckerSoundness            string   `json:"checker_soundness,omitempty"`
	CheckerMethod               string   `json:"checker_method,omitempty"`
	CheckerSeconds              float64  `json:"checker_seconds,omitempty"`
	GroundTruthFlowCount        int      `json:"ground_truth_flow_count,omitempty"`
	ConstructiveFlowCount       *int     `json:"constructive_flow_count,omitempty"`
	ConstructiveExcessFlowCount *int     `json:"constructive_excess_flow_count,omitempty"`
	ConstructiveSeconds         *float64 `json:"constructive_seconds,omitempty"`
}

func runPrecision(args []string) error {
	fs := flag.NewFlagSet("precision", flag.ContinueOnError)
	f, constructiveReportPath, err := parseCommon(fs, args, true)
	if err != nil {
		return err
	}
	targets, err := buildTargets(f.repo, f.summaries, f.checkReport, constructiveReportPath, true)
	if err != nil {
		return err
	}
	// precision only cares about correctness, not timing.
	for ti := range targets {
		for ri := range targets[ti].Results {
			targets[ti].Results[ri].CheckerSeconds = 0
			targets[ti].Results[ri].ConstructiveSeconds = nil
		}
	}
	return writeOutput(f.out, evalOutput{RQ: "checker-precision", Repo: f.repo, Targets: targets})
}

func runEfficiency(args []string) error {
	fs := flag.NewFlagSet("efficiency", flag.ContinueOnError)
	f, constructiveReportPath, err := parseCommon(fs, args, true)
	if err != nil {
		return err
	}
	targets, err := buildTargets(f.repo, f.summaries, f.checkReport, constructiveReportPath, false)
	if err != nil {
		return err
	}
	// efficiency only cares about timing: strip the precision-only fields.
	for ti := range targets {
		for ri := range targets[ti].Results {
			targets[ti].Results[ri].CheckerSoundness = ""
			targets[ti].Results[ri].CheckerMethod = ""
			targets[ti].Results[ri].GroundTruthFlowCount = 0
			targets[ti].Results[ri].ConstructiveFlowCount = nil
			targets[ti].Results[ri].ConstructiveExcessFlowCount = nil
		}
	}
	return writeOutput(f.out, evalOutput{RQ: "checker-efficiency", Repo: f.repo, Targets: targets})
}

func runAblation(args []string) error {
	fs := flag.NewFlagSet("ablation", flag.ContinueOnError)
	f, _, err := parseCommon(fs, args, false)
	if err != nil {
		return err
	}
	targets, err := buildTargets(f.repo, f.summaries, f.checkReport, "", false)
	if err != nil {
		return err
	}
	// ablation only cares about name + checker_method.
	for ti := range targets {
		for ri := range targets[ti].Results {
			r := &targets[ti].Results[ri]
			*r = result{Name: r.Name, CheckerMethod: r.CheckerMethod}
		}
	}
	return writeOutput(f.out, evalOutput{RQ: "checker-ablation", Repo: f.repo, Targets: targets})
}

// rawCheckResult mirrors analysis/check's rawSoundnessResult JSON shape (the relevant subset of
// fields; CalleeResults/Unsoundness are not needed here).
type rawCheckResult struct {
	Func        string
	SummaryName string
	Want        map[string][]string
	Got         map[string][]string
	Soundness   string
	Method      string
	Elapsed     time.Duration
}

// checkReport maps a target name (build target, not summary name) to its results, or null if
// argot check failed to analyze that target at all.
type checkReport map[string][]rawCheckResult

func loadCheckReport(path string) (map[string][]rawCheckResult, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var raw map[string]*[]rawCheckResult
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	report := make(map[string][]rawCheckResult, len(raw))
	var nullTargets []string
	for name, results := range raw {
		if results == nil {
			nullTargets = append(nullTargets, name)
			continue
		}
		report[name] = *results
	}
	return report, nullTargets, nil
}

// groupBySummaryName groups a check-report.json's flat per-target result lists by SummaryName
// (the top-level summary entry each result was checked against). For an interface method, every
// concrete implementation's result shares the same SummaryName (the interface method's own
// name); for a plain function, SummaryName equals Func.
func groupBySummaryName(report map[string][]rawCheckResult) map[string][]rawCheckResult {
	grouped := make(map[string][]rawCheckResult)
	for _, results := range report {
		for _, r := range results {
			grouped[r.SummaryName] = append(grouped[r.SummaryName], r)
		}
	}
	return grouped
}

// groupByFunc indexes a check-report.json's flat per-target result lists by Func, keeping only
// the first result per function (matching run_experiment.py's constructive_matches[0]
// behavior: each function is only checked once per run-constructive invocation).
func groupByFunc(report map[string][]rawCheckResult) map[string]rawCheckResult {
	byFunc := make(map[string]rawCheckResult)
	for _, results := range report {
		for _, r := range results {
			if _, ok := byFunc[r.Func]; !ok {
				byFunc[r.Func] = r
			}
		}
	}
	return byFunc
}

func buildTargets(
	repo string,
	summariesPaths []string,
	checkReportPath string,
	constructiveReportPath string,
	computeExcessFlows bool,
) ([]target, error) {
	var entries []summaries.FrontendDataflowSummary
	for _, p := range summariesPaths {
		es, err := summaries.ParseSummariesFile(p)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		entries = append(entries, es...)
	}

	checkReport, nullTargets, err := loadCheckReport(checkReportPath)
	if err != nil {
		return nil, err
	}
	for _, name := range nullTargets {
		fmt.Fprintf(os.Stderr,
			"warning: target %q has no results in the check report "+
				"(argot check likely failed to build it); see the .log file\n", name)
	}
	checkBySummary := groupBySummaryName(checkReport)

	var constructiveByFunc map[string]rawCheckResult
	if constructiveReportPath != "" {
		constructiveReport, nullConstructiveTargets, err := loadCheckReport(constructiveReportPath)
		if err != nil {
			return nil, err
		}
		for _, name := range nullConstructiveTargets {
			fmt.Fprintf(os.Stderr,
				"warning: target %q has no results in the constructive report; "+
					"see the .log file\n", name)
		}
		constructiveByFunc = groupByFunc(constructiveReport)
	}

	targets := []target{}
	for _, entry := range entries {
		kind := "function"
		if _, ok := entry.(summaries.IfaceMethodFlowSummary); ok {
			kind = "interface"
		}
		name := entry.Name()

		results := []result{}
		for _, cr := range checkBySummary[name] {
			results = append(results, mergeResult(cr, constructiveByFunc, computeExcessFlows))
		}

		targets = append(targets, target{SummaryName: name, Kind: kind, Results: results})
	}
	return targets, nil
}

func mergeResult(
	cr rawCheckResult, constructiveByFunc map[string]rawCheckResult, computeExcessFlows bool,
) result {
	want, err := toDetailedSummary(cr.Want)
	if err != nil {
		// Should not happen: cr.Want was produced by argot check's own serializer. Fall back
		// to a flow count based purely on the raw string map rather than failing the whole run.
		fmt.Fprintf(os.Stderr, "warning: could not parse Want for %s: %v\n", cr.Func, err)
	}

	r := result{
		Name:                 cr.Func,
		CheckerSoundness:     cr.Soundness,
		CheckerMethod:        cr.Method,
		CheckerSeconds:       cr.Elapsed.Seconds(),
		GroundTruthFlowCount: flowCount(cr.Want),
	}

	constructiveResult, ok := constructiveByFunc[cr.Func]
	if !ok {
		return r
	}
	constructiveFlowCount := flowCount(constructiveResult.Got)
	constructiveSeconds := constructiveResult.Elapsed.Seconds()
	r.ConstructiveFlowCount = &constructiveFlowCount
	r.ConstructiveSeconds = &constructiveSeconds

	if computeExcessFlows {
		excess := 0
		if err == nil {
			got, gotErr := toDetailedSummary(constructiveResult.Got)
			if gotErr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not parse Got for %s: %v\n", cr.Func, gotErr)
			} else {
				excess = len(want.UncoveredFlows(got))
			}
		}
		r.ConstructiveExcessFlowCount = &excess
	}
	return r
}

// toDetailedSummary parses a check-report.json flow map (as produced by report.go's rawFlows)
// back into a DetailedSummary, using summaries.ParseSummaryNode -- the inverse of
// SummaryNode.String(), which is what rawFlows uses to flatten flows to strings.
func toDetailedSummary(flows map[string][]string) (summaries.DetailedSummary, error) {
	parsed := make(map[summaries.SummaryNode][]summaries.SummaryNode, len(flows))
	for from, tos := range flows {
		fromNode, err := summaries.ParseSummaryNode(from)
		if err != nil {
			return summaries.DetailedSummary{}, err
		}
		toNodes := make([]summaries.SummaryNode, 0, len(tos))
		for _, to := range tos {
			toNode, err := summaries.ParseSummaryNode(to)
			if err != nil {
				return summaries.DetailedSummary{}, err
			}
			toNodes = append(toNodes, toNode)
		}
		parsed[fromNode] = toNodes
	}
	return summaries.DetailedSummary{Flows: parsed}, nil
}

// flowCount counts individual flow edges in a raw {source: [dest, ...]} map, without needing to
// parse the summary nodes.
func flowCount(flows map[string][]string) int {
	n := 0
	for _, tos := range flows {
		n += len(tos)
	}
	return n
}

func writeOutput(path string, out evalOutput) error {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Println("Wrote", path)
	return nil
}
