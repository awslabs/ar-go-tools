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
// `argot check` (via run-check/run-constructive in run_experiment.py) into the JSON schemas used
// by the paper's evaluation questions.
//
// Each subcommand has its own result type because the evaluation questions measure distinct
// properties:
//
//	eval-checker precision          --repo R --summaries FILE... --check-report FILE --out FILE
//	eval-checker efficiency         --repo R --summaries FILE... --check-report FILE --constructive-report FILE --out FILE
//	eval-checker ablation           --repo R --summaries FILE... --check-report FILE --out FILE
//	eval-checker llm-effectiveness  --repo R --summaries FILE... --check-report FILE --constructive-report FILE --out FILE
//
// Flow comparison stays in Go so it can reuse summaries.DetailedSummary.UncoveredFlows. That
// comparison accounts for field subsumption and summary-node normalization; duplicating it in
// Python would risk changing the meaning of excess flows.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/check"
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
	case "llm-effectiveness":
		err = runLLMEffectiveness(os.Args[2:])
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
	fmt.Fprintln(os.Stderr,
		"usage: eval-checker <precision|efficiency|ablation|llm-effectiveness> [flags]")
}

// commonFlags are the flags shared by all subcommands.
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

func parseCommon(
	fs *flag.FlagSet,
	args []string,
	needConstructive bool,
) (commonFlags, string, error) {
	var f commonFlags
	var constructiveReport string
	fs.StringVar(&f.repo, "repo", "", "repo name (for the output's \"repo\" field)")
	fs.Var(&f.summaries, "summaries", "path to a ground-truth summaries YAML file (repeatable)")
	fs.StringVar(&f.checkReport, "check-report", "", "path to check-report.json")
	if needConstructive {
		fs.StringVar(
			&constructiveReport,
			"constructive-report",
			"",
			"path to constructive check-report.json",
		)
	}
	fs.StringVar(&f.out, "out", "", "path to write the output JSON to")
	if err := fs.Parse(args); err != nil {
		return f, "", err
	}
	if f.repo == "" || len(f.summaries) == 0 || f.checkReport == "" || f.out == "" {
		return f, "", fmt.Errorf(
			"missing required flag(s); need -repo, -summaries, -check-report, -out",
		)
	}
	if needConstructive && constructiveReport == "" {
		return f, "", fmt.Errorf("missing required flag -constructive-report")
	}
	return f, constructiveReport, nil
}

// evaluationTarget groups results by the ground-truth summary they evaluate. An interface-method
// summary may have multiple concrete implementation results; a plain function has at most one.
type evaluationTarget[T any] struct {
	SummaryName string `json:"summary_name"`
	Kind        string `json:"kind"`
	Results     []T    `json:"results"`
}

// evalCheckerPrecisionResult answers rq:checker-precision: whether the soundness checker
// classifies a known-sound, most-precise ground-truth model as sound.
type evalCheckerPrecisionResult struct {
	Name             string          `json:"name"`
	CheckerSoundness check.Soundness `json:"checker_soundness"`
}

type evalCheckerPrecisionOutput struct {
	RQ      string                                         `json:"rq"`
	Repo    string                                         `json:"repo"`
	Targets []evaluationTarget[evalCheckerPrecisionResult] `json:"targets"`
}

// evalCheckerEfficiencyResult answers rq:checker-efficiency by pairing soundness-checker and
// constructive-analysis durations for the same concrete function.
type evalCheckerEfficiencyResult struct {
	Name                string   `json:"name"`
	CheckerSeconds      float64  `json:"checker_seconds"`
	ConstructiveSeconds *float64 `json:"constructive_seconds,omitempty"`
}

type evalCheckerEfficiencyOutput struct {
	RQ      string                                          `json:"rq"`
	Repo    string                                          `json:"repo"`
	Targets []evaluationTarget[evalCheckerEfficiencyResult] `json:"targets"`
}

// evalCheckerAblationResult answers rq:checker-ablation by recording which checker method
// discharged each concrete check.
type evalCheckerAblationResult struct {
	Name          string `json:"name"`
	CheckerMethod string `json:"checker_method"`
}

type evalCheckerAblationOutput struct {
	RQ      string                                        `json:"rq"`
	Repo    string                                        `json:"repo"`
	Targets []evaluationTarget[evalCheckerAblationResult] `json:"targets"`
}

// evalLLMEffectivenessResult answers rq:llm-effectiveness for one ground-truth-selected summary.
// Interface results are collapsed over reachable concrete implementations: CheckerSoundness is
// sound iff every reachable implementation is sound, and flow counts use unions across those
// implementations. ExcessFlowCount is present only when every reachable implementation has a
// proven-sound checker verdict (sound or soundy).
type evalLLMEffectivenessResult struct {
	Name                         string          `json:"name"`
	ReachableImplementationCount int             `json:"reachable_implementation_count"`
	CheckerSoundness             check.Soundness `json:"checker_soundness"`
	LLMFlowCount                 int             `json:"llm_flow_count"`
	ConstructiveFlowCount        *int            `json:"constructive_flow_count,omitempty"`
	ExcessFlowCount              *int            `json:"excess_flow_count,omitempty"`
}

type evalLLMEffectivenessOutput struct {
	RQ      string                                         `json:"rq"`
	Repo    string                                         `json:"repo"`
	Targets []evaluationTarget[evalLLMEffectivenessResult] `json:"targets"`
}

func runPrecision(args []string) error {
	fs := flag.NewFlagSet("precision", flag.ContinueOnError)
	f, _, err := parseCommon(fs, args, false)
	if err != nil {
		return err
	}
	entries, checkBySummary, err := loadEvaluationInputs(f.summaries, f.checkReport)
	if err != nil {
		return err
	}

	targets := make([]evaluationTarget[evalCheckerPrecisionResult], 0, len(entries))
	for _, entry := range entries {
		results := make([]evalCheckerPrecisionResult, 0, len(checkBySummary[entry.Name()]))
		for _, cr := range checkBySummary[entry.Name()] {
			results = append(results, evalCheckerPrecisionResult{
				Name:             cr.Func,
				CheckerSoundness: cr.Soundness,
			})
		}
		targets = append(targets, evaluationTarget[evalCheckerPrecisionResult]{
			SummaryName: entry.Name(),
			Kind:        summaryKind(entry),
			Results:     results,
		})
	}

	return writeOutput(f.out, evalCheckerPrecisionOutput{
		RQ: "checker-precision", Repo: f.repo, Targets: targets,
	})
}

func runEfficiency(args []string) error {
	fs := flag.NewFlagSet("efficiency", flag.ContinueOnError)
	f, constructiveReportPath, err := parseCommon(fs, args, true)
	if err != nil {
		return err
	}
	entries, checkBySummary, err := loadEvaluationInputs(f.summaries, f.checkReport)
	if err != nil {
		return err
	}
	constructiveByFunc, err := loadConstructiveResults(constructiveReportPath)
	if err != nil {
		return err
	}

	targets := make([]evaluationTarget[evalCheckerEfficiencyResult], 0, len(entries))
	for _, entry := range entries {
		results := make([]evalCheckerEfficiencyResult, 0, len(checkBySummary[entry.Name()]))
		for _, cr := range checkBySummary[entry.Name()] {
			result := evalCheckerEfficiencyResult{
				Name:           cr.Func,
				CheckerSeconds: cr.Elapsed.Seconds(),
			}
			if constructive, ok := constructiveByFunc[cr.Func]; ok {
				seconds := constructive.Elapsed.Seconds()
				result.ConstructiveSeconds = &seconds
			}
			results = append(results, result)
		}
		targets = append(targets, evaluationTarget[evalCheckerEfficiencyResult]{
			SummaryName: entry.Name(),
			Kind:        summaryKind(entry),
			Results:     results,
		})
	}

	return writeOutput(f.out, evalCheckerEfficiencyOutput{
		RQ: "checker-efficiency", Repo: f.repo, Targets: targets,
	})
}

func runAblation(args []string) error {
	fs := flag.NewFlagSet("ablation", flag.ContinueOnError)
	f, _, err := parseCommon(fs, args, false)
	if err != nil {
		return err
	}
	entries, checkBySummary, err := loadEvaluationInputs(f.summaries, f.checkReport)
	if err != nil {
		return err
	}

	targets := make([]evaluationTarget[evalCheckerAblationResult], 0, len(entries))
	for _, entry := range entries {
		results := make([]evalCheckerAblationResult, 0, len(checkBySummary[entry.Name()]))
		for _, cr := range checkBySummary[entry.Name()] {
			results = append(results, evalCheckerAblationResult{
				Name: cr.Func, CheckerMethod: cr.Method,
			})
		}
		targets = append(targets, evaluationTarget[evalCheckerAblationResult]{
			SummaryName: entry.Name(),
			Kind:        summaryKind(entry),
			Results:     results,
		})
	}

	return writeOutput(f.out, evalCheckerAblationOutput{
		RQ: "checker-ablation", Repo: f.repo, Targets: targets,
	})
}

func runLLMEffectiveness(args []string) error {
	fs := flag.NewFlagSet("llm-effectiveness", flag.ContinueOnError)
	f, constructiveReportPath, err := parseCommon(fs, args, true)
	if err != nil {
		return err
	}
	entries, checkBySummary, err := loadEvaluationInputs(f.summaries, f.checkReport)
	if err != nil {
		return err
	}
	constructiveByFunc, err := loadConstructiveResults(constructiveReportPath)
	if err != nil {
		return err
	}

	targets := make([]evaluationTarget[evalLLMEffectivenessResult], 0, len(entries))
	for _, entry := range entries {
		checkResults := checkBySummary[entry.Name()]
		results := []evalLLMEffectivenessResult{}
		if len(checkResults) > 0 {
			result, err := buildLLMEffectivenessResult(entry.Name(), checkResults, constructiveByFunc)
			if err != nil {
				return err
			}
			results = append(results, result)
		}
		targets = append(targets, evaluationTarget[evalLLMEffectivenessResult]{
			SummaryName: entry.Name(),
			Kind:        summaryKind(entry),
			Results:     results,
		})
	}

	return writeOutput(f.out, evalLLMEffectivenessOutput{
		RQ: "llm-effectiveness", Repo: f.repo, Targets: targets,
	})
}

// rawCheckResult mirrors analysis/check's rawSoundnessResult JSON shape (the relevant subset of
// fields; CalleeResults/Unsoundness are not needed here).
type rawCheckResult struct {
	Func        string
	SummaryName string
	Want        map[string][]string
	Got         map[string][]string
	Soundness   check.Soundness
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

func loadEvaluationInputs(
	summaryPaths []string,
	checkReportPath string,
) ([]summaries.FrontendDataflowSummary, map[string][]rawCheckResult, error) {
	var entries []summaries.FrontendDataflowSummary
	for _, path := range summaryPaths {
		parsed, err := summaries.ParseSummariesFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		entries = append(entries, parsed...)
	}

	report, nullTargets, err := loadCheckReport(checkReportPath)
	if err != nil {
		return nil, nil, err
	}
	warnNullTargets(nullTargets, "check")
	return entries, groupBySummaryName(report), nil
}

func loadConstructiveResults(path string) (map[string]rawCheckResult, error) {
	report, nullTargets, err := loadCheckReport(path)
	if err != nil {
		return nil, err
	}
	warnNullTargets(nullTargets, "constructive")
	return groupByFunc(report), nil
}

func warnNullTargets(targets []string, reportKind string) {
	for _, name := range targets {
		fmt.Fprintf(
			os.Stderr,
			"warning: target %q has no results in the %s report; see the .log file\n",
			name,
			reportKind,
		)
	}
}

// groupBySummaryName groups a check-report.json's flat per-target result lists by SummaryName.
// For an interface method, every reachable concrete implementation shares the interface method's
// SummaryName; for a plain function, SummaryName equals Func.
func groupBySummaryName(report map[string][]rawCheckResult) map[string][]rawCheckResult {
	grouped := make(map[string][]rawCheckResult)
	for _, results := range report {
		for _, result := range results {
			grouped[result.SummaryName] = append(grouped[result.SummaryName], result)
		}
	}
	return grouped
}

// groupByFunc indexes a check-report.json's flat per-target result lists by Func, keeping only
// the first result per function. A function is checked once per run-constructive invocation.
func groupByFunc(report map[string][]rawCheckResult) map[string]rawCheckResult {
	byFunc := make(map[string]rawCheckResult)
	for _, results := range report {
		for _, result := range results {
			if _, exists := byFunc[result.Func]; !exists {
				byFunc[result.Func] = result
			}
		}
	}
	return byFunc
}

func summaryKind(entry summaries.FrontendDataflowSummary) string {
	if _, ok := entry.(summaries.IfaceMethodFlowSummary); ok {
		return "interface"
	}
	return "function"
}

func buildLLMEffectivenessResult(
	summaryName string,
	checkResults []rawCheckResult,
	constructiveByFunc map[string]rawCheckResult,
) (evalLLMEffectivenessResult, error) {
	llmSummaries := make([]summaries.DetailedSummary, 0, len(checkResults))
	for _, checkResult := range checkResults {
		llmSummary, err := toDetailedSummary(checkResult.Want)
		if err != nil {
			return evalLLMEffectivenessResult{}, fmt.Errorf(
				"parsing LLM summary for %s: %w", checkResult.Func, err,
			)
		}
		llmSummaries = append(llmSummaries, llmSummary)
	}

	checkerSoundness := aggregateCheckerSoundness(checkResults)
	llmUnion := unionDetailedSummaries(llmSummaries)
	result := evalLLMEffectivenessResult{
		Name:                         summaryName,
		ReachableImplementationCount: len(checkResults),
		CheckerSoundness:             checkerSoundness,
		LLMFlowCount:                 detailedFlowCount(llmUnion),
	}
	if !isProvenSound(checkerSoundness) {
		return result, nil
	}

	constructiveSummaries := make([]summaries.DetailedSummary, 0, len(checkResults))
	for _, checkResult := range checkResults {
		constructiveResult, ok := constructiveByFunc[checkResult.Func]
		if !ok {
			return evalLLMEffectivenessResult{}, fmt.Errorf(
				"checker marked %s %s, but no constructive result exists for %s",
				summaryName,
				checkerSoundness,
				checkResult.Func,
			)
		}
		constructiveSummary, err := toDetailedSummary(constructiveResult.Got)
		if err != nil {
			return evalLLMEffectivenessResult{}, fmt.Errorf(
				"parsing constructive summary for %s: %w", checkResult.Func, err,
			)
		}
		constructiveSummaries = append(constructiveSummaries, constructiveSummary)
	}

	constructiveUnion := unionDetailedSummaries(constructiveSummaries)
	constructiveFlowCount := detailedFlowCount(constructiveUnion)
	// The two sound over-approximations need not be nested: the constructive analysis may have
	// false-positive flows absent from a sound LLM model. Precision therefore counts only the
	// opposite difference: LLM flows that the constructive model does not cover.
	excessFlowCount := len(constructiveUnion.UncoveredFlows(llmUnion))
	result.ConstructiveFlowCount = &constructiveFlowCount
	result.ExcessFlowCount = &excessFlowCount
	return result, nil
}

// aggregateCheckerSoundness preserves the checker's four verdicts while collapsing reachable
// interface implementations. Error and unsound dominate; otherwise any soundy implementation
// makes the aggregate soundy, and only all-sound implementations aggregate to sound.
func aggregateCheckerSoundness(results []rawCheckResult) check.Soundness {
	aggregate := check.Sound
	for _, result := range results {
		switch result.Soundness {
		case check.Error:
			return check.Error
		case check.Unsound:
			aggregate = check.Unsound
		case check.Soundy:
			if aggregate == check.Sound {
				aggregate = check.Soundy
			}
		case check.Sound:
			// Keep the current aggregate.
		default:
			return check.Error
		}
	}
	return aggregate
}

// isProvenSound matches the checker's semantics: both sound and soundy prove every must-not-flow;
// soundy additionally records an unsoundness-risk feature. Both verdicts therefore pass the
// LLM-effectiveness precision gate.
func isProvenSound(soundness check.Soundness) bool {
	return soundness == check.Sound || soundness == check.Soundy
}

// unionDetailedSummaries computes a flow-set union and removes duplicate edges. This is used to
// collapse reachable concrete interface implementations into one LLM-effectiveness row.
func unionDetailedSummaries(all []summaries.DetailedSummary) summaries.DetailedSummary {
	unionSets := make(map[summaries.SummaryNode]map[summaries.SummaryNode]struct{})
	for _, summary := range all {
		for from, tos := range summary.Flows {
			if unionSets[from] == nil {
				unionSets[from] = make(map[summaries.SummaryNode]struct{})
			}
			for _, to := range tos {
				unionSets[from][to] = struct{}{}
			}
		}
	}

	flows := make(map[summaries.SummaryNode][]summaries.SummaryNode, len(unionSets))
	for from, toSet := range unionSets {
		flows[from] = make([]summaries.SummaryNode, 0, len(toSet))
		for to := range toSet {
			flows[from] = append(flows[from], to)
		}
	}
	return summaries.DetailedSummary{Flows: flows}
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

func detailedFlowCount(summary summaries.DetailedSummary) int {
	count := 0
	for _, tos := range summary.Flows {
		count += len(tos)
	}
	return count
}

func writeOutput(path string, out any) error {
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
