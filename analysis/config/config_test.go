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
	"path/filepath"
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
	cid1 := CodeIdentifier{"", "a", "", "b", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_emptyMatchesAny(t *testing.T) {
	cid1 := CodeIdentifier{"", "a", "b", "i", "c", "d", "e", "", "", nil}
	cid2 := CodeIdentifier{"", "de", "234jbn", "ef", "23kjb", "d", "234", "", "", nil}
	cidEmpty := CodeIdentifier{}
	checkEqualOnNonEmptyFields(t, cid1, cidEmpty)
	checkEqualOnNonEmptyFields(t, cid2, cidEmpty)
}

func TestCodeIdentifier_equalOnNonEmptyFields_oneDiff(t *testing.T) {
	cid1 := CodeIdentifier{"", "a", "b", "", "", "", "", "", "", nil}
	cid2 := CodeIdentifier{"", "a", "", "", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkNotEqualOnNonEmptyFields(t, cid2, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes(t *testing.T) {
	cid1 := CodeIdentifier{"", "main", "b", "", "", "", "", "", "", nil}
	cid1bis := CodeIdentifier{"", "command-line-arguments", "b", "", "", "", "", "", "", nil}
	cid2 := CodeIdentifier{"", "(main)|(command-line-arguments)$", "", "", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes_withContexts(t *testing.T) {
	cid1 := CodeIdentifier{"main-package", "main", "", "b", "", "", "", "", "", nil}
	cid1bis := CodeIdentifier{"main", "command-line-arguments", "", "b", "", "", "", "", "", nil}
	cid2 := CodeIdentifier{"mai.*", "(main)|(command-line-arguments)$", "", "", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func mkConfig(sanitizers []CodeIdentifier, sinks []CodeIdentifier, sources []CodeIdentifier) Config {
	c := NewDefault()
	ts := TaintSpec{}
	ts.Sanitizers = sanitizers
	ts.Sinks = sinks
	ts.Sources = sources
	c.MaxDepth = DefaultMaxCallDepth
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

func TestLoadWithReports(t *testing.T) {
	c := NewDefault()
	c.ReportsDir = "example-report"
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

//gocyclo:ignore
func TestLoadFullConfig(t *testing.T) {
	fileName, config, err := loadFromTestDir("full-config.yaml")
	if config == nil || err != nil {
		t.Errorf("Could not load %s", fileName)
		return
	}
	if config.LogLevel != int(TraceLevel) {
		t.Error("full config should have set trace")
	}
	if !config.SkipInterprocedural {
		t.Error("full config should have set skiipinterprocedural")
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
	if len(config.DataflowSpecs) != 2 {
		t.Error("full config should specify two dataflow spec files")
	}
	if config.MaxDepth != 42 {
		t.Error("full config should set max-depth to 42")
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
	if len(config.TaintTrackingProblems) != 1 ||
		len(config.TaintTrackingProblems[0].Sinks) != 1 ||
		len(config.TaintTrackingProblems[0].Validators) != 1 ||
		len(config.TaintTrackingProblems[0].Sanitizers) != 1 ||
		len(config.TaintTrackingProblems[0].Sources) != 1 {
		t.Error("full config should have one element in each of sinks, validators, sanitizers and sources")
	}
	if !config.SourceTaintsArgs {
		t.Error("full config should have source-taints-args set")
	}
	if !config.SilenceWarn {
		t.Error("full config should have silence-warn set to true")
	}
	if !config.IgnoreNonSummarized {
		t.Errorf("full config should have set ignorenonsummarized")
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

func TestLoadMisc(t *testing.T) {
	//
	testLoadOneFile(
		t,
		"config.yaml",
		mkConfig(
			[]CodeIdentifier{{"", "a", "", "b", "", "", "", "", "", nil}},
			[]CodeIdentifier{{"", "c", "", "d", "", "", "", "", "", nil}},
			[]CodeIdentifier{},
		),
	)
	//
	testLoadOneFile(t,
		"config2.json",
		mkConfig(
			[]CodeIdentifier{{"", "x", "", "a", "", "b", "", "", "", nil}},
			[]CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", nil}},
			[]CodeIdentifier{{"", "p", "", "a", "", "", "", "", "", nil},
				{"", "p2", "", "a", "", "", "", "", "", nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config2.yaml",
		mkConfig(
			[]CodeIdentifier{{"", "x", "", "a", "", "b", "", "", "", nil}},
			[]CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", nil}},
			[]CodeIdentifier{{"", "p", "", "a", "", "", "", "", "", nil},
				{"", "p2", "", "a", "", "", "", "", "", nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config3.yaml",
		Config{
			TaintTrackingProblems: []TaintSpec{
				{
					Sanitizers: []CodeIdentifier{{"", "pkg1", "", "Foo", "Obj", "", "", "", "", nil}},
					Sinks: []CodeIdentifier{{"", "y", "", "b", "", "", "", "", "", nil},
						{"", "x", "", "", "Obj1", "", "", "", "", nil}},
					Sources: []CodeIdentifier{
						{"", "some/package", "", "SuperMethod", "", "", "", "", "", nil},

						{"", "some/other/package", "", "", "", "OneField", "ThatStruct", "", "", nil},
						{"", "some/other/package", "Interface", "", "", "", "", "", "", nil},
					},
					FailOnImplicitFlow: false,
				},
			},
			Options: Options{
				PkgFilter:   "a",
				MaxDepth:    DefaultMaxCallDepth,
				SilenceWarn: false,
			},
			EscapeConfig: NewEscapeConfig(),
		},
	)
	// Test configuration file for static-commands
	osExecCid := CodeIdentifier{"", "os/exec", "", "Command", "", "", "", "", "", nil}
	cfg := NewDefault()
	cfg.StaticCommandsProblems = []StaticCommandsSpec{{[]CodeIdentifier{osExecCid}}}
	testLoadOneFile(t, "config-find-osexec.yaml", *cfg)
}
