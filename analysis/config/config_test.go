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
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

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
	cid1 := CodeIdentifier{"a", "b", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_emptyMatchesAny(t *testing.T) {
	cid1 := CodeIdentifier{"a", "b", "c", "d", "e", "", "", nil}
	cid2 := CodeIdentifier{"de", "234jbn", "23kjb", "d", "234", "", "", nil}
	cidEmpty := CodeIdentifier{}
	checkEqualOnNonEmptyFields(t, cid1, cidEmpty)
	checkEqualOnNonEmptyFields(t, cid2, cidEmpty)
}

func TestCodeIdentifier_equalOnNonEmptyFields_oneDiff(t *testing.T) {
	cid1 := CodeIdentifier{"a", "b", "", "", "", "", "", nil}
	cid2 := CodeIdentifier{"a", "", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkNotEqualOnNonEmptyFields(t, cid2, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes(t *testing.T) {
	cid1 := CodeIdentifier{"main", "b", "", "", "", "", "", nil}
	cid1bis := CodeIdentifier{"command-line-arguments", "b", "", "", "", "", "", nil}
	cid2 := CodeIdentifier{"(main)|(command-line-arguments)$", "", "", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func mkConfig(sanitizers []CodeIdentifier, sinks []CodeIdentifier, sources []CodeIdentifier) Config {
	c := NewDefault()
	c.Sanitizers = sanitizers
	c.Sinks = sinks
	c.Sources = sources
	c.MaxDepth = DefaultMaxCallDepth
	return *c
}

func loadFromTestDir(t *testing.T, filename string) (string, *Config, error) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	configFileName := filepath.Join(filepath.Join(testdata, "config-examples"), filename)
	config, err := Load(configFileName)
	return configFileName, config, err
}

func testLoadOneFile(t *testing.T, filename string, expected Config) {
	// set default log level that may not be specified
	if expected.LogLevel == 0 {
		expected.LogLevel = int(InfoLevel)
	}
	configFileName, config, err := loadFromTestDir(t, filename)
	if err != nil {
		t.Errorf("Error loading %s: %v", configFileName, err)
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
		t.Errorf("Error in %s:\n%s is not\n%s\n", filename, c1, c2)
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
	c, err := Load("someconfig.yaml")
	if c != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load non existent file.")
	}
}

func TestLoadBadFormatFileReturnsError(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	configFileName := filepath.Join(filepath.Join(testdata, "config-examples"), "bad_format.yaml")
	config, err := Load(configFileName)

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
	_, config, err := loadFromTestDir(t, "config_with_reports_bad_dir.yaml")
	if config != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load config with a report dir that has a non-existing" +
			"directory name")
	}
}

func TestLoadWithNoSpecifiedReportsDir(t *testing.T) {
	fileName, config, err := loadFromTestDir(t, "config_with_reports_no_dir_spec.yaml")
	if config == nil || err != nil {
		t.Errorf("Could not load %s", fileName)
		return
	}
	if !config.ReportNoCalleeSites {
		t.Errorf("Expected reportnocalleesites to be true in %s", fileName)
	}
	if config.ReportNoCalleeFile() != config.nocalleereportfile {
		t.Errorf("ReportNoCalleeFile should return private value")
	}
	if config.ReportsDir == "" {
		t.Errorf("Expected reportsdir to be non-empty after loading config %s", fileName)
	}
	// Remove temporary files
	os.Remove(config.nocalleereportfile)
	os.Remove(config.ReportsDir)
}

//gocyclo:ignore
func TestLoadFullConfig(t *testing.T) {
	fileName, config, err := loadFromTestDir(t, "full-config.yaml")
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
		t.Error("full config should have set reportcoverage")
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
		t.Error("full config should set MaxDepth to 42")
	}
	if config.MaxAlarms != 16 {
		t.Error("full config should set MaxAlarms to 16")
	}
	if !config.MatchCoverageFilter("argot/analysis/analyzers.go") {
		t.Error("full config coverage filter should match files in argot")
	}
	if config.PkgFilter == "" {
		t.Error("full config should specify a pkgfilter")
	}
	if !config.MatchPkgFilter("argot/analysis/analyzers.go") {
		t.Error("full config coverage filter should match files in analysis")
	}
	if len(config.Sinks) != 1 || len(config.Validators) != 1 || len(config.Sanitizers) != 1 ||
		len(config.Sources) != 1 {
		t.Error("full config should have one element in each of sinks, validators, sanitizers and sources")
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
			[]CodeIdentifier{{"a", "b", "", "", "", "", "", nil}},
			[]CodeIdentifier{{"c", "d", "", "", "", "", "", nil}},
			[]CodeIdentifier{},
		),
	)
	//
	testLoadOneFile(t,
		"config2.yaml",
		mkConfig(
			[]CodeIdentifier{{"x", "a", "", "b", "", "", "", nil}},
			[]CodeIdentifier{{"y", "b", "", "", "", "", "", nil}},
			[]CodeIdentifier{{"p", "a", "", "", "", "", "", nil},
				{"p2", "a", "", "", "", "", "", nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config3.yaml",
		Config{
			Sanitizers: []CodeIdentifier{{"pkg1", "Foo", "Obj", "", "", "", "", nil}},
			Sinks: []CodeIdentifier{{"y", "b", "", "", "", "", "", nil},
				{"x", "", "Obj1", "", "", "", "", nil}},
			Sources: []CodeIdentifier{
				{"some/package", "SuperMethod", "", "", "", "", "", nil},

				{"some/other/package", "", "", "OneField", "ThatStruct", "", "", nil},
			},
			PkgFilter: "a",
			MaxDepth:  DefaultMaxCallDepth,
			Warn:      true,
		},
	)
	// Test configuration file for static-commands
	osExecCid := CodeIdentifier{"os/exec", "Command", "", "", "", "", "", nil}
	cfg := NewDefault()
	cfg.StaticCommands = []CodeIdentifier{osExecCid}
	testLoadOneFile(t, "config-find-osexec.yaml", *cfg)
}
