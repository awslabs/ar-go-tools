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

package config

import (
	"embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata
var testfsys embed.FS

func checkEqualOnNonEmptyFields(t *testing.T, cid1 CodeIdentifier, cid2 CodeIdentifier) {
	cid2c := compileRegexes(cid2)
	if !cid1.equalOnNonEmptyFields(cid2c) {
		t.Errorf("%v should be equal modulo empty fields to %v", cid1, cid2)
	}
}

func checkNotEqualOnNonEmptyFields(t *testing.T, cid1 CodeIdentifier, cid2 CodeIdentifier) {
	cid2c := compileRegexes(cid2)
	if cid1.equalOnNonEmptyFields(cid2c) {
		t.Errorf("%v should not be equal modulo empty fields to %v", cid1, cid2)
	}
}

func TestCodeIdentifier_equalOnNonEmptyFields_selfEquals(t *testing.T) {
	cid1 := CodeIdentifier{"", "a", "", "b", "", "", "", "", "", "", "", nil, nil}
	checkEqualOnNonEmptyFields(t, cid1, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_emptyMatchesAny(t *testing.T) {
	cid1 := CodeIdentifier{"", "a", "b", "i", "c", "d", "e", "", "", "", "", nil, nil}
	cid2 := CodeIdentifier{"", "de", "234jbn", "ef", "23kjb", "d", "234", "", "", "", "", nil, nil}
	cidEmpty := CodeIdentifier{}
	checkEqualOnNonEmptyFields(t, cid1, cidEmpty)
	checkEqualOnNonEmptyFields(t, cid2, cidEmpty)
}

func TestCodeIdentifier_equalOnNonEmptyFields_oneDiff(t *testing.T) {
	cid1 := CodeIdentifier{"", "a", "b", "", "", "", "", "", "", "", "", nil, nil}
	cid2 := CodeIdentifier{"", "a", "", "", "", "", "", "", "", "", "", nil, nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkNotEqualOnNonEmptyFields(t, cid2, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes(t *testing.T) {
	cid1 := CodeIdentifier{"", "main", "b", "", "", "", "", "", "", "", "", nil, nil}
	cid1bis := CodeIdentifier{"", "command-line-arguments", "b", "", "", "", "", "", "", "", "", nil, nil}
	cid2 := CodeIdentifier{"", "(main)|(command-line-arguments)$", "", "", "", "", "", "", "", "", "", nil, nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes_withContexts(t *testing.T) {
	cid1 := CodeIdentifier{"main-package", "main", "", "b", "", "", "", "", "", "", "", nil, nil}
	cid1bis := CodeIdentifier{"main", "command-line-arguments", "", "b", "", "", "", "", "", "", "", nil, nil}
	cid2 := CodeIdentifier{"mai.*", "(main)|(command-line-arguments)$", "", "", "", "", "", "", "", "", "", nil, nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func mkConfig(sanitizers []CodeIdentifier, sinks []CodeIdentifier, sources []CodeIdentifier) Config {
	c := NewDefault()
	ts := TaintSpec{}
	ts.Sanitizers = sanitizers
	ts.Sinks = sinks
	ts.Sources = sources
	c.TaintTrackingProblems = []TaintSpec{ts}
	return *c
}

func loadFromTestDir(filename string) (string, *Config, error) {
	filename = filepath.Join("testdata", filename)
	b, err := testfsys.ReadFile(filename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read file %v: %v", filename, err)
	}
	config, err := Load(filename, b)
	if err != nil {
		return filename, nil, fmt.Errorf("failed to load file %v: %v", filename, err)
	}
	return filename, config, err
}

func testLoadOneFile(t *testing.T, filename string, expected Config) {
	// set default log level that may not be specified
	if expected.LogLevel == 0 {
		expected.LogLevel = int(InfoLevel)
	}
	configFileName, config, err := loadFromTestDir(filename)
	if err != nil {
		t.Errorf("Error loading %q: %v", configFileName, err)
	}
	c1, err1 := yaml.Marshal(config)
	c2, err2 := yaml.Marshal(expected)
	if err1 != nil {
		t.Errorf("Error marshalling %v", config)
	}
	if err2 != nil {
		t.Errorf("Error marshalling %v", expected)
	}
	if string(c1) != string(c2) {
		t.Errorf("Error in %q:\n%q is not\n%q\n", filename, c1, c2)
	}
}

func TestNewDefault(t *testing.T) {
	// Test that all methods work on the default config file, and check default values
	c := NewDefault()
	if c.CoverageFilter != "" {
		t.Errorf("Default for CoverageFilter should be empty")
	}
	if c.nocalleereportfile != "" {
		t.Errorf("Default for nocallereportfile should be empty")
	}
}

func TestLoadNonExistentFileReturnsError(t *testing.T) {
	name := filepath.Join("testdata", "bad_format.yaml")
	b, err := testfsys.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read file %v: %v", name, err)
	}
	c, err := Load(name, b)
	if c != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load non existent file.")
	}
}

func TestLoadBadFormatFileReturnsError(t *testing.T) {
	name := filepath.Join("testdata", "bad_format.yaml")
	b, err := testfsys.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read file %v: %v", name, err)
	}
	config, err := Load(name, b)
	if config != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load a badly formatted file.")
	}
}

func TestLoadDuplicateTagsReturnsError(t *testing.T) {
	name := filepath.Join("testdata", "invalid_config_duplicate_tags.yaml")
	b, err := testfsys.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read file %v: %v", name, err)
	}
	_, err = Load(name, b)
	if err == nil {
		t.Fatalf("Expected error and nil value when trying to load a config with duplicate problem tags.")
	}
	if !strings.Contains(err.Error(), "used for multiple problems") {
		t.Errorf("Error message should explain error caused by duplicate, but got %s", err)
	}
}

func TestLoadInvalidSeverityReturnsError(t *testing.T) {
	name := filepath.Join("testdata", "invalid_config_invalid_sev.yaml")
	b, err := testfsys.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read file %v: %v", name, err)
	}
	_, err = Load(name, b)
	if err == nil {
		t.Fatalf("Expected error and nil value when trying to load a config with duplicate problem tags.")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("Error message should explain error caused by invalid severity label, but got %s", err)
	}
}

func TestLoadWithProjectRoot(t *testing.T) {
	_, config, err := loadFromTestDir("test_project_root_loading.yaml")
	if config == nil || err != nil {
		t.Fatalf("encountered error when loading config with project root specified: %s", err)
	}
}

func TestLoadWithUndefinedTargetReturnsError(t *testing.T) {
	_, _, err := loadFromTestDir("config_undefined_target.yaml")
	if err == nil {
		t.Fatalf("expected error when loading config with undefined target")
	}
	if !strings.Contains(err.Error(), "target \"foo\" for problem with tag") {
		t.Errorf("config with undefined target should have explicit error message not %s", err)
	}
}

func TestLoadVersionBefore_v0_3_0_Errors(t *testing.T) {
	_, config, err := loadFromTestDir("config_before_v0_3_0.yaml")
	if config != nil || err == nil {
		t.Fatalf("Expected error and nil value when trying to load config with bad format")
	}
	msg1 := "Please consult documentation and update the config file"
	if !strings.Contains(err.Error(), msg1) {
		t.Errorf("Error message:\n%s\nshould contain %s", err, msg1)
	}

	_, configJson, errJson := loadFromTestDir("config_before_v0_3_0.json")
	if configJson != nil || errJson == nil {
		t.Fatalf("Expected error and nil value when trying to load config with bad format")
	}
	if !strings.Contains(errJson.Error(), msg1) {
		t.Errorf("Error message:\n%s\nshould contain %s", errJson, msg1)
	}
}

func TestLoadWithReports(t *testing.T) {
	c := NewDefault()
	wd, _ := os.Getwd()
	c.ReportsDir = path.Join(wd, "testdata/example-report")
	c.ReportPaths = true
	testLoadOneFile(t, "config_with_reports.yaml", *c)
	if c.RelPath("example-report") != "example-report" {
		t.Errorf("Reports dir should be relative to config file when specified")
	}
	os.Remove("example-report")
}

func TestLoadWithReportNoDirReturnsError(t *testing.T) {
	_, config, err := loadFromTestDir("config_with_reports_bad_dir.yaml")
	if config != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load config with a report dir that has a non-existing" +
			"directory name")
	}
}

func TestLoadWithNoSpecifiedReportsDir(t *testing.T) {
	fileName, config, err := loadFromTestDir("config_with_reports_no_dir_spec.yaml")
	if config == nil || err != nil {
		t.Errorf("Could not load %q", fileName)
		return
	}
	if !config.ReportNoCalleeSites {
		t.Errorf("Expected report-no-callee-sites to be true in %q", fileName)
	}
	if config.ReportNoCalleeFile() != config.nocalleereportfile {
		t.Errorf("ReportNoCalleeFile should return private value")
	}
	if config.ReportsDir == "" {
		t.Errorf("Expected reports-dir to be non-empty after loading config %q", fileName)
	}
	// Remove temporary files
	os.Remove(config.nocalleereportfile)
	os.Remove(config.ReportsDir)
}

func TestLoadSyntacticConfigYaml(t *testing.T) {
	fileName, config, err := loadFromTestDir("syntactic-config.yaml")
	if config == nil || err != nil {
		t.Errorf("could not load %s", fileName)
		return
	}
	if config.ReportsDir == "" {
		t.Errorf("expected reports-dir to be non-empty after loading config %q", fileName)
	}
	if config.LogLevel != int(TraceLevel) {
		t.Error("syntactic config should have set trace log level")
	}
	if config.MaxAlarms != 2 {
		t.Error("syntactic config should have set 2 max alarms")
	}
	if !config.SilenceWarn {
		t.Error("syntactic config should have set silence-warn to true")
	}

	if len(config.SyntacticProblems.StructInitProblems) == 0 {
		t.Error("syntactic config should have struct-init problems")
	}

	for _, sspec := range config.SyntacticProblems.StructInitProblems {
		if sspec.Struct.Type == "" {
			t.Error("syntactic config should have a struct-init struct type")
		}
		if len(sspec.FieldsSet) == 0 {
			t.Error("syntactic config should have a struct-init fields-set list")
		}
		for _, fspec := range sspec.FieldsSet {
			if fspec.Field == "" {
				t.Error("syntactic config should have a struct-init fields-set field")
			}
			if fspec.Value.Package == "" {
				t.Error("syntactic config should have a struct-init fields-set value package")
			}
			if fspec.Value.Const == "" {
				t.Error("syntactic config should have a struct-init fields-set value const")
			}
		}

	}
	os.Remove(config.ReportsDir)
}

//gocyclo:ignore
func TestLoadFullConfigYaml(t *testing.T) {
	fileName, config, err := loadFromTestDir("full-config.yaml")
	if config == nil || err != nil {
		t.Errorf("Could not load %s: %s", fileName, err)
		return
	}
	if config.LogLevel != int(TraceLevel) {
		t.Error("full config should have set trace")
	}
	if !config.ReportCoverage {
		t.Error("full config should have set report-coverage")
	}
	if !config.ReportNoCalleeSites {
		t.Error("full config should have set reportnocalleesites")
	}
	if !config.ReportPaths {
		t.Error("full config should have set reportpaths")
	}
	if config.CoverageFilter == "" {
		t.Error("full config should specify a coverage prefix")
	}
	if len(config.UserSpecs) != 2 {
		t.Error("full config should specify two dataflow spec files")
	}
	if config.UnsafeMaxDepth != 42 {
		t.Error("full config should set unsafe-max-depth to 42")
	}
	if config.MaxAlarms != 16 {
		t.Error("full config should set MaxAlarms to 16")
	}
	if !config.MatchCoverageFilter("argot/analysis/analyzers.go") {
		t.Error("full config coverage filter should match files in argot")
	}
	if config.PkgFilter == "" {
		t.Error("full config should specify a pkg-filter")
	}
	if !config.MatchPkgFilter("argot/analysis/analyzers.go") {
		t.Error("full config coverage filter should match files in analysis")
	}
	// Test taint tracking problems
	if len(config.TaintTrackingProblems) != 1 ||
		len(config.TaintTrackingProblems[0].Sinks) != 1 ||
		len(config.TaintTrackingProblems[0].Validators) != 1 ||
		len(config.TaintTrackingProblems[0].Sanitizers) != 1 ||
		len(config.TaintTrackingProblems[0].Sources) != 1 {
		t.Error("full config should have one element in each of sinks, validators, sanitizers and sources")
	}
	if config.TaintTrackingProblems[0].UnsafeMaxDepth != 1 {
		t.Error("analysis option unsafe-max-depth should be 1 for taint-tracking-problem")
	}
	if config.TaintTrackingProblems[0].Severity != High {
		t.Error("taint-tracking-problem severity should be HIGH")
	}
	if !config.TaintTrackingProblems[0].SourceTaintsArgs {
		t.Error("analysis option source-taints-args should be true for taint-tracking-problem")
	}
	if config.TaintTrackingProblems[0].Description == "taint-tracking-problem-1" {
		t.Error("tag of taint tracking problem should be taint-tracking-problem-1")
	}
	if strings.Contains(config.TaintTrackingProblems[0].Tag, "A taint tracking problem") {
		t.Error("description should be set for taint-tracking-problem")
	}
	// Test slicing
	if len(config.SlicingProblems) != 1 {
		t.Error("there should be exactly one slicing problem.")
	}
	if len(config.SlicingProblems[0].BacktracePoints) != 1 {
		t.Error("the slicing problem should have exactly one backtrace point.")
	}
	if config.SlicingProblems[0].Tag != "slicing-problem-1" {
		t.Error("the slicing problem should have tag slicing-problem-1")
	}
	if !strings.Contains(config.SlicingProblems[0].Description, "A slicing problem") {
		t.Error("description should be set for the slicing problem")
	}
	if !config.SilenceWarn {
		t.Error("full config should have silence-warn set to true")
	}
	if !config.UseEscapeAnalysis {
		t.Errorf("full config should have set useescapeaanalysis")
	}

	if !config.SummarizeOnDemand {
		t.Errorf("full config should set summarize-on-demand")
	}
	// Remove temporary files
	os.Remove(config.nocalleereportfile)
	os.Remove(config.ReportsDir)
}

func TestLoadFullConfigYamlEqualsJson(t *testing.T) {
	_, yamlConfig, yamlErr := loadFromTestDir("full-config.yaml")
	_, jsonConfig, jsonErr := loadFromTestDir("full-config.json")
	if jsonErr != nil {
		t.Fatalf("failed to load json config")
	}
	if yamlErr != nil {
		t.Fatalf("failed to load yaml config")
	}
	jsonConfig.sourceFile = ""
	yamlConfig.sourceFile = ""
	if jsonConfig.ReportCoverage != yamlConfig.ReportCoverage &&
		jsonConfig.SilenceWarn != yamlConfig.SilenceWarn &&
		jsonConfig.LogLevel != yamlConfig.LogLevel &&
		jsonConfig.UnsafeMaxDepth != yamlConfig.Options.UnsafeMaxDepth &&
		jsonConfig.UnsafeMaxDepth != yamlConfig.UnsafeMaxDepth {
		t.Errorf("config options in json and yaml should be the same")
	}
}

func TestLoadMisc(t *testing.T) {
	//
	testLoadOneFile(
		t,
		"config.yaml",
		mkConfig(
			[]CodeIdentifier{{"", "a", "", "b", "", "", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{{"", "c", "", "d", "", "", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{},
		),
	)
	//
	testLoadOneFile(t,
		"config2.json",
		mkConfig(
			[]CodeIdentifier{{"", "x", "", "a", "", "b", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{{"", "p", "", "a", "", "", "", "", "", "", "", nil, nil},
				{"", "p2", "", "a", "", "", "", "", "", "", "", nil, nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config2.yaml",
		mkConfig(
			[]CodeIdentifier{{"", "x", "", "a", "", "b", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", "", "", nil, nil}},
			[]CodeIdentifier{{"", "p", "", "a", "", "", "", "", "", "", "", nil, nil},
				{"", "p2", "", "a", "", "", "", "", "", "", "", nil, nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config3.yaml",
		Config{
			DataflowProblems: DataflowProblems{
				TaintTrackingProblems: []TaintSpec{
					{
						Sanitizers: []CodeIdentifier{{"", "pkg1", "", "Foo", "Obj", "", "", "", "", "", "", nil, nil}},
						Sinks: []CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", "", "", nil, nil},
							{"", "x", "", "", "Obj1", "", "", "", "", "", "", nil, nil}},
						Sources: []CodeIdentifier{
							{"", "some/package", "", "SuperMethod", "", "", "", "", "", "", "", nil, nil},

							{"", "some/other/package", "", "", "", "OneField", "ThatStruct", "", "", "", "", nil, nil},
							{"", "some/other/package", "Interface", "", "", "", "", "", "", "", "", nil, nil},
						},
						FailOnImplicitFlow: false,
					},
				},
			},
			Options: Options{
				PkgFilter: "a",
				AnalysisProblemOptions: AnalysisProblemOptions{
					UnsafeMaxDepth:           DefaultSafeMaxDepth,
					MaxEntrypointContextSize: DefaultSafeMaxEntrypointContextSize,
				},
				SilenceWarn: false,
			},
			EscapeConfig:  NewEscapeConfig(),
			PointerConfig: NewPointerConfig(),
		},
	)
	// Test configuration file for static-commands
	osExecCid := CodeIdentifier{"", "os/exec", "", "Command", "", "", "", "", "", "", "", nil, nil}
	cfg := NewDefault()
	cfg.StaticCommandsProblems = []StaticCommandsSpec{{[]CodeIdentifier{osExecCid}}}
	testLoadOneFile(t, "config-find-osexec.yaml", *cfg)
}
