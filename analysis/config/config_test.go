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
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config/analysiscfg"
	"github.com/awslabs/ar-go-tools/analysis/config/specs"
	"gopkg.in/yaml.v3"
)

//go:embed testdata
var testfsys embed.FS

func mkConfig(
	sanitizers []specs.ParsedCodeIdentifier,
	sinks []specs.ParsedCodeIdentifier,
	sources []specs.ParsedCodeIdentifier,
) parsedConfig {
	c := &NewDefault().parsedConfig
	ts := specs.ParsedTaintSpec{}
	ts.Sanitizers = sanitizers
	ts.Sinks = sinks
	ts.Sources = sources
	c.TaintTrackingProblems = []specs.ParsedTaintSpec{ts}
	return *c
}

func loadFromTestDir(filename string, overrides *CmdLineOverrides) (string, *Config, error) {
	filename = filepath.Join("testdata", filename)
	b, err := testfsys.ReadFile(filename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read file %v: %v", filename, err)
	}
	config, err := Load(filename, b, overrides)
	if err != nil {
		return filename, nil, fmt.Errorf("failed to load file %v: %v", filename, err)
	}
	return filename, config, err
}

func testLoadOneFile(t *testing.T, filename string, expected parsedConfig) {
	// set default log level that may not be specified
	if expected.LogLevel == 0 {
		expected.LogLevel = int(InfoLevel)
	}
	configFileName, config, err := loadFromTestDir(filename, nil)
	if err != nil {
		t.Errorf("Error loading %q: %v", configFileName, err)
	}
	c1, err1 := yaml.Marshal(config.parsedConfig)
	c2, err2 := yaml.Marshal(expected)
	if err1 != nil {
		t.Errorf("Error marshalling %v", config.parsedConfig)
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
	c, err := Load(name, b, nil)
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
	config, err := Load(name, b, nil)
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
	_, err = Load(name, b, nil)
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
	_, err = Load(name, b, nil)
	if err == nil {
		t.Fatalf("Expected error and nil value when trying to load a config with duplicate problem tags.")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("Error message should explain error caused by invalid severity label, but got %s", err)
	}
}

func TestLoadWithProjectRoot(t *testing.T) {
	_, config, err := loadFromTestDir("test_project_root_loading.yaml", nil)
	if config == nil || err != nil {
		t.Fatalf("encountered error when loading config with project root specified: %s", err)
	}
}

func TestLoadWithUndefinedTargetReturnsError(t *testing.T) {
	_, _, err := loadFromTestDir("config_undefined_target.yaml", nil)
	if err == nil {
		t.Fatalf("expected error when loading config with undefined target")
	}
	if !strings.Contains(err.Error(), "target \"foo\" for problem with tag") {
		t.Errorf("config with undefined target should have explicit error message not %s", err)
	}
}

func TestLoadVersionBefore_v0_3_0_Errors(t *testing.T) {
	_, config, err := loadFromTestDir("config_before_v0_3_0.yaml", nil)
	if config != nil || err == nil {
		t.Fatalf("Expected error and nil value when trying to load config with bad format")
	}
	msg1 := "Please consult documentation and update the config file"
	if !strings.Contains(err.Error(), msg1) {
		t.Errorf("Error message:\n%s\nshould contain %s", err, msg1)
	}

	_, configJson, errJson := loadFromTestDir("config_before_v0_3_0.json", nil)
	if configJson != nil || errJson == nil {
		t.Fatalf("Expected error and nil value when trying to load config with bad format")
	}
	if !strings.Contains(errJson.Error(), msg1) {
		t.Errorf("Error message:\n%s\nshould contain %s", errJson, msg1)
	}
}

func TestLoadWithReports(t *testing.T) {
	c := &NewDefault().parsedConfig
	wd, _ := os.Getwd()
	c.ReportsDir = filepath.Join(wd, "testdata/example-report")
	c.ReportPaths = true
	testLoadOneFile(t, "config_with_reports.yaml", *c)
	cmp, err := c.Compile(nil)
	if err != nil {
		t.Fatalf("Error compiling config: %s", err)
	}
	if !strings.Contains(cmp.RelPath("test"), "analysis") {
		t.Errorf("Reports dir should be relative to config file when specified: %s",
			cmp.RelPath("test"))
	}
	os.Remove("example-report")
}

func TestLoadWithReportNoDirReturnsError(t *testing.T) {
	_, config, err := loadFromTestDir("config_with_reports_bad_dir.yaml", nil)
	if config != nil || err == nil {
		t.Errorf("Expected error and nil value when trying to load config with a report dir that has a non-existing" +
			"directory name")
	}
}

func TestLoadWithNoSpecifiedReportsDir(t *testing.T) {
	fileName, config, err := loadFromTestDir("config_with_reports_no_dir_spec.yaml", nil)
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

func TestLoadWithReportsDirOverride(t *testing.T) {
	reportsDir := "test-cmdline-dir"
	fileName, config, err := loadFromTestDir("config_with_reports_dir.yaml", &CmdLineOverrides{
		LogLevel:   0,
		ReportsDir: reportsDir,
	})
	if config == nil || err != nil {
		t.Errorf("Could not load %q", fileName)
		return
	}
	if config.ReportsDir != reportsDir {
		t.Errorf("Expected reports-dir to be %s after loading config %q with override, not %s",
			reportsDir, fileName, config.ReportsDir)
	}
	// Remove temporary files
	os.Remove(config.nocalleereportfile)
	os.Remove(config.ReportsDir)
}

func TestLoadSyntacticConfigYaml(t *testing.T) {
	fileName, config, err := loadFromTestDir("syntactic-config.yaml", nil)
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
	fileName, config, err := loadFromTestDir("full-config.yaml", nil)
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
	if config.TaintTrackingProblems[0].Severity != analysiscfg.High {
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
	_, yamlConfig, yamlErr := loadFromTestDir("full-config.yaml", nil)
	_, jsonConfig, jsonErr := loadFromTestDir("full-config.json", nil)
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
			[]specs.ParsedCodeIdentifier{{Package: "a", Method: "b"}},
			[]specs.ParsedCodeIdentifier{{Package: "c", Method: "d"}},
			[]specs.ParsedCodeIdentifier{},
		),
	)
	//
	testLoadOneFile(t,
		"config2.json",
		mkConfig(
			[]specs.ParsedCodeIdentifier{{Package: "x", Method: "a", Field: "b"}},
			[]specs.ParsedCodeIdentifier{{Package: "y", Method: "b"}},
			[]specs.ParsedCodeIdentifier{
				{Package: "p", Method: "a"},
				{Package: "p2", Method: "a"},
			},
		),
	)
	//
	testLoadOneFile(t,
		"config2.yaml",
		mkConfig(
			[]specs.ParsedCodeIdentifier{{Package: "x", Method: "a", Field: "b"}},
			[]specs.ParsedCodeIdentifier{{Package: "y", Method: "b"}},
			[]specs.ParsedCodeIdentifier{
				{Package: "p", Method: "a"},
				{Package: "p2", Method: "a"},
			},
		),
	)
	//
	testLoadOneFile(t,
		"config3.yaml",
		parsedConfig{
			ParsedDataflowProblems: specs.ParsedDataflowProblems{
				TaintTrackingProblems: []specs.ParsedTaintSpec{
					{
						Sanitizers: []specs.ParsedCodeIdentifier{
							{Package: "pkg1", Method: "Foo", Receiver: "Obj"},
						},
						Sinks: []specs.ParsedCodeIdentifier{
							{Package: "y", Method: "b"},
							{Package: "x", Receiver: "Obj1"},
						},
						Sources: []specs.ParsedCodeIdentifier{
							{Package: "some/package", Method: "SuperMethod"},
							{Package: "some/other/package", Field: "OneField", Type: "ThatStruct"},
							{Package: "some/other/package", Interface: "Interface"},
						},
						FailOnImplicitFlow: false,
					},
				},
			},
			Options: Options{
				PkgFilter: "a",
				ProblemCfg: analysiscfg.ProblemCfg{
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
	osExecCid := specs.ParsedCodeIdentifier{Package: "os/exec", Method: "Command", Target: specs.Target{}, Enclosing: specs.CallingContext{}}
	cfg := &NewDefault().parsedConfig
	cfg.StaticCommandsProblems = []specs.StaticCommandsSpec{{StaticCommands: []specs.ParsedCodeIdentifier{osExecCid}}}
	testLoadOneFile(t, "config-find-osexec.yaml", *cfg)
}

// TestLoadNew tests loading the new code identifier format.
func TestLoadNew(t *testing.T) {
	want := &NewDefault().parsedConfig
	want.ParsedDataflowProblems = specs.ParsedDataflowProblems{
		SlicingProblems: []specs.ParsedSlicingSpec{
			{
				Tag:         "tag-name",
				Description: "Sample description",
				BacktracePoints: []specs.ParsedCodeIdentifier{
					{
						Target: specs.Target{
							Kind:    specs.CallKind,
							Package: "os",
							Method:  "Mkdir",
							Objects: []specs.TargetObject{
								{
									Kind:  specs.ArgumentKind,
									Name:  "name",
									Index: 0,
									Type:  "string",
								},
							},
						},
						Enclosing: specs.CallingContext{
							Package: "package-name",
							Method:  "method",
						},
					},
					{
						Target: specs.Target{
							Kind:    specs.CallKind,
							Package: "os",
							Method:  "MkdirAll",
							Objects: []specs.TargetObject{
								{
									Kind:  specs.ArgumentKind,
									Name:  "path",
									Index: 0,
									Type:  "string",
								},
							},
						},
						Enclosing: specs.CallingContext{
							PackageRegex: "package.*",
							MethodRegex:  ".*",
						},
					},
				},
			},
		},
	}

	testLoadOneFile(t, "config-new.yaml", *want)
}
