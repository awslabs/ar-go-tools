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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"gopkg.in/yaml.v3"
)

var (
	// The global config file
	configFile string
)

// SetGlobalConfig sets the global config filename
func SetGlobalConfig(filename string) {
	configFile = filename
}

// LoadGlobal loads the config file that has been set by SetGlobalConfig
func LoadGlobal() (*Config, error) {
	cfg, err := LoadFromFiles(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load global config file %v: %v", configFile, err)
	}

	return cfg, err
}

// EscapeConfig holds the options relative to the escape analysis configuration
type EscapeConfig struct {

	// Functions controls behavior override, keyed by .String() (e.g. command-line-arguments.main,
	// (*package.Type).Method, etc). A value of "summarize" means process normally, "unknown" is
	// treat as unanalyzed, and "noop" means calls are assumed to have no escape effect (and return
	// nil if they have a pointer-like return).
	Functions map[string]string `json:"functions"`

	// The maximum size of an escape summary. If a function attempts to compute a larger summary, it
	// will be replaced by a conservative, unsummarized stub.
	SummaryMaximumSize int `json:"summary-maximum-size"`

	// Allow/blocklist of packages, keyed by package path. A value of true means allow, false is
	// block, and not present is default behavior.
	PkgFilter string `json:"pkg-filter"`

	// if the PkgFilter is specified
	pkgFilterRegex *regexp.Regexp
}

// NewEscapeConfig returns a new escape config with a preset summary maximum size and initialized Functions map.
func NewEscapeConfig() *EscapeConfig {
	return &EscapeConfig{
		Functions:          map[string]string{},
		PkgFilter:          "",
		SummaryMaximumSize: 100000,
	}
}

// NewPointerConfig returns a new escape config with default parameters:
// - the filter of no-effect functions is nil.
func NewPointerConfig() *PointerConfig {
	return &PointerConfig{UnsafeNoEffectFunctions: nil}
}

// MatchPkgFilter matches a package name against a configuration.
// Returns true if the package name matches the filter.
func (c *EscapeConfig) MatchPkgFilter(pkgname string) bool {
	if c.pkgFilterRegex != nil {
		return c.pkgFilterRegex.MatchString(pkgname)
	} else if c.PkgFilter != "" {
		return strings.HasPrefix(pkgname, c.PkgFilter)
	} else {
		return true
	}
}

// Config contains lists of sanitizers, sinks, sources, static commands to identify ...
// To add elements to a config file, add fields to this struct.
// If some field is not defined in the config file, it will be empty/zero in the struct.
// private fields are not populated from a yaml file, but computed after initialization
type Config struct {
	Options

	sourceFile string

	// nocalleereportfile is a file name in ReportsDir when ReportNoCalleeSites is true
	nocalleereportfile string

	// if the PkgFilter is specified
	pkgFilterRegex *regexp.Regexp

	// if the CoverageFilter is specified
	coverageFilterRegex *regexp.Regexp

	// the path to the root folder
	root string

	// EscapeConfig contains the escape-analysis specific configuration parameters
	EscapeConfig *EscapeConfig

	// ImmutabilityProblems lists the immutability analysis problems.
	ImmutabilityProblems []ImmutabilitySpec `yaml:"immutability-problems" json:"immutability-problems"`

	// DiodonPassThroughProblems lists the Diodon pass-through analysis problems.
	DiodonPassThroughProblems []DiodonPassThroughSpec `yaml:"diodon-pass-through-problems" json:"diodon-pass-through-problems"`

	// PointerConfig contains the pointer-analysis specific configuration parameters
	PointerConfig *PointerConfig `yaml:"pointer-config" json:"pointer-config"`

	// StaticCommandsProblems lists the static commands problems
	StaticCommandsProblems []StaticCommandsSpec `yaml:"static-commands-problems" json:"static-commands-problems"`

	SyntacticProblems SyntacticSpecs `yaml:"syntactic-problems" json:"syntactic-problems"`

	// DataflowProblems specifies the dataflow problems to solve in the config
	DataflowProblems `yaml:"dataflow-problems" json:"dataflow-problems"`

	// Targets specifies the set of targets that may be used in the config
	Targets []TargetSpec
}

// AnalysisProblemOptions are the options that are specific to an analysis problem.
type AnalysisProblemOptions struct {
	// MaxAlarms sets a limit for the number of alarms reported by an analysis.  If MaxAlarms > 0, then at most
	// MaxAlarms will be reported. Otherwise, if MaxAlarms <= 0, it is ignored.
	//
	// This setting does not affect soundness, since event with max-alarms:1, at least one path will be reported if
	// there is some potential alarm-causing result.
	MaxAlarms int `xml:"max-alarms,attr" yaml:"max-alarms" json:"max-alarms"`

	// UnsafeMaxDepth sets a limit for the number of function call depth explored during the analysis.
	// The default is -1, and any value less than 0 is safe: the analysis will be sound and explore call depth
	// without bounds.
	//
	// Setting UnsafeMaxDepth to a limit larger than 0 will yield unsound results, but can be useful to use the tool
	// as a checking mechanism. Limiting the call depth will usually yield fewer false positives.
	UnsafeMaxDepth int `xml:"unsafe-max-depth,attr" yaml:"unsafe-max-depth" json:"unsafe-max-depth"`

	// MaxEntrypointContextSize sets the maximum context (call stack) size used when searching for entry points with context.
	// This only impacts precision of the returned results.
	//
	// If MaxEntrypointContextSize is < 0, it is ignored.
	// If MaxEntrypointContextSize is 0 is specified by the user, the value is ignored, and a default internal value is used.
	// If MaxEntrypointContextSize is > 0, then the limit in the callstack size for the context is used.
	MaxEntrypointContextSize int `xml:"max-entrypoint-context-size,attr" yaml:"max-entrypoint-context-size" json:"max-entrypoint-context-size"`
}

// PointerConfig is the pointer analysis specific configuration.
type PointerConfig struct {
	// UnsafeNoEffectFunctions is a list of function names that produce no constraints in the pointer analysis.
	// Use at your own risk: using this option *may* make the analysis unsound. However, if you are confident
	// that the listed function does not have any effect on aliasing, adding it here may reduce false positives.
	UnsafeNoEffectFunctions []string `yaml:"unsafe-no-effect-functions" json:"unsafe-no-effect-functions"`

	// Reflection is the reflection option of the pointer analysis: when true, reflection aperators are handled
	// soundly, but analysis time will increase dramatically.
	Reflection bool
}

// ImmutabilitySpec contains code identifiers for the immutability analysis.
type ImmutabilitySpec struct {
	// Tag is the identifier of the problem
	Tag string
	// Severity is the severity of the finding
	Severity Severity
	// Description is a human-readable description of the problem
	Description string
	// Targets are the targets of the analysis
	Targets []string

	// Values is the list of identifiers representing which values whose
	// modifications should be reported.
	Values []CodeIdentifier

	// Filters contains a list of filters that prevents some identifiers from being analyzed.
	Filters []CodeIdentifier
}

// IsValue returns true if the code identifier cid matches a value according to spec s.
// Ignores the context field because its meaning is overloaded in the immutability analysis.
func (s ImmutabilitySpec) IsValue(cid CodeIdentifier) bool {
	cid.Context = ""
	vals := funcutil.Map(s.Values, func(cid CodeIdentifier) CodeIdentifier {
		cid.Context = ""
		return cid
	})
	return ExistsCid(vals, cid.equalOnNonEmptyFields)
}

// SpecTag returns the specification's tag
func (s ImmutabilitySpec) SpecTag() string {
	return s.Tag
}

// SpecTargets returns the specification's targets
func (s ImmutabilitySpec) SpecTargets() []string {
	return s.Targets
}

// SpecSeverity returns the specification's severity
func (s ImmutabilitySpec) SpecSeverity() Severity {
	return s.Severity
}

// DiodonPassThroughSpec contains code identifiers for the Diodon pass-through analysis.
type DiodonPassThroughSpec struct {
	// Tag is the identifier of the problem
	Tag string
	// Severity is the severity of the finding
	Severity Severity
	// Description is a human-readable description of the problem
	Description string
	// Targets are the targets of the analysis
	Targets []string

	// AppFunctions is the list of identifiers representing which functions are
	// part of the App.
	AppFunctions []CodeIdentifier `yaml:"app-functions" json:"app-functions"`

	// CoreFunctions is the list of identifiers representing which functions are
	// part of the Core.
	CoreFunctions []CodeIdentifier `yaml:"core-functions" json:"core-functions"`

	// CoreAllocFunction is the function that allocates the Core instance's memory.
	CoreAllocFunction CodeIdentifier `yaml:"core-alloc-function" json:"core-alloc-function"`

	// CoreApiFunctions is the list of identifiers representing
	// which functions are part of the Core API.
	// The return values and/or parameters establish permissions for heap
	// locations allocated within the context of the Core API function.
	CoreApiFunctions []CodeIdentifier `yaml:"core-api-functions" json:"core-api-functions"`

	// AppAccessFilters contains a list of identifiers representing which functions
	// in the App should not be analyzed for invalid accesses due to
	// imprecision in the pointer analysis.
	AppAccessFilters []CodeIdentifier `yaml:"app-access-filters" json:"app-access-filters"`

	// CoreAllocFilters contains a list of identifiers representing which
	// functions in the Core should not be analyzed for allocation sites due to
	// imprecision in the pointer analysis.
	CoreAllocFilters []CodeIdentifier `yaml:"core-alloc-filters" json:"core-alloc-filters"`

	// NoLeakFunctions contains a list of identifiers representing which
	// functions in the Core cannot leak an allocation except via its return
	// parameters.
	NoLeakFunctions []CodeIdentifier `yaml:"no-leak-functions" json:"no-leak-functions"`
}

// SpecTag returns the specification's tag
func (s DiodonPassThroughSpec) SpecTag() string {
	return s.Tag
}

// SpecTargets returns the specification's targets
func (s DiodonPassThroughSpec) SpecTargets() []string {
	return s.Targets
}

// SpecSeverity returns the specification's severity
func (s DiodonPassThroughSpec) SpecSeverity() Severity {
	return s.Severity
}

// StaticCommandsSpec contains code identifiers for the problem of identifying which commands are static
type StaticCommandsSpec struct {
	// StaticCommands is the list of identifiers to be considered as command execution for the static commands analysis
	// (not used)
	StaticCommands []CodeIdentifier `yaml:"static-commands" json:"static-commands"`
}

// SyntacticSpecs contains specs for the different syntactic analysis problems.
type SyntacticSpecs struct {
	// StructInitSpecs is the list of specs for the struct inititialization problems.
	StructInitProblems []StructInitSpec `yaml:"struct-inits" json:"struct-inits"`
}

// StructInitSpec contains specs for the problem of tracking a specific struct initialization.
type StructInitSpec struct {
	// Tag is the identifier of the problem
	Tag string
	// Severity is the severity of the finding when some struct is not initialized properly
	Severity Severity
	// Description is a human-readable description of the problem
	Description string
	Targets     []string
	// Struct is the struct type whose initialization should be tracked.
	Struct CodeIdentifier
	// FieldsSet is the list of the fields of Struct that must always be set to a specific value.
	FieldsSet []FieldsSetSpec `yaml:"fields-set" json:"fields-set"`
	// Filters is the list of values that the analysis does not track.
	Filters []CodeIdentifier
}

// SpecTag returns the struct init specification's tag
func (si StructInitSpec) SpecTag() string {
	return si.Tag
}

// SpecTargets returns the struct init specification's targets
func (si StructInitSpec) SpecTargets() []string {
	return si.Targets
}

// SpecSeverity returns the struct init specification's severity
func (si StructInitSpec) SpecSeverity() Severity {
	return si.Severity
}

// FieldsSetSpec contains the code identifiers for the problem of tracking how a
// struct's fields are initialized.
type FieldsSetSpec struct {
	// Field is the struct field name whose value must be initialized to the Value.
	Field string
	// Value is the value that Field must always be set to.
	// We only support static values for now (e.g., constants and static functions).
	Value CodeIdentifier
}

// A TargetSpec is a set of files the form a Go program together with a name to identify the target in the configuration
// file.
type TargetSpec struct {
	// Name identifies the target in the rest of the configuration file
	Name string
	// Files identifies the target's files
	Files []string
}

// Options holds the global options for analyses
// embeds AnalysisProblemOptions
type Options struct {
	AnalysisProblemOptions `xml:"analysis-options,attr" yaml:"analysis-options" json:"analysis-options"`

	// Path to a JSON file that has the escape configuration (allow/blocklist)
	EscapeConfigFile string `xml:"escape-config,attr" yaml:"escape-config" json:"escape-config"`

	// CoverageFilter can be used to filter which packages will be reported in the coverage. If non-empty,
	// coverage will only for those packages that match CoverageFilter
	CoverageFilter string `xml:"coverage-filter,attr" yaml:"coverage-filter" json:"coverage-filter"`

	// Loglevel controls the verbosity of the tool
	LogLevel int `xml:"log-level,attr" yaml:"log-level" json:"log-level"`

	// PkgFilter is a filter for the taint analysis to build summaries only for the function whose package match the
	// prefix. This is a global option because it is used during the first intra-procedural passes of the analysis.
	PkgFilter string `xml:"pkg-filter,attr" yaml:"pkg-filter" json:"pkg-filter"`

	// ReportCoverage specifies whether coverage should be reported. If true, then a file names coverage-*.out will
	// be created in the report directory, containing the coverage data generated by the analysis
	ReportCoverage bool `xml:"report-coverage,attr" yaml:"report-coverage" json:"report-coverage"`

	// ReportNoCalleeSites specifies whether the tool should report where it does not find any callee.
	ReportNoCalleeSites bool `xml:"report-no-callee-sites,attr" yaml:"report-no-callee-sites" json:"report-no-callee-sites"`

	// ReportPaths specifies whether the taint flows should be reported in separate files. For each taint flow, a new
	// file named taint-*.out will be generated with the trace from source to sink
	ReportPaths bool `xml:"report-paths,attr" yaml:"report-paths" json:"report-paths"`

	// ReportSummaries can be set to true, in which case summaries will be reported in a file names summaries-*.out in
	// the reports directory
	ReportSummaries bool `xml:"report-summaries,attr" yaml:"report-summaries" json:"report-summaries"`

	// ReportsDir is the directory where all the reports will be stored. If the yaml config file this config struct has
	// been loaded does not specify a ReportsDir but sets any Report* option to true, then ReportsDir will be created
	// in the folder the binary is called.
	ReportsDir string `xml:"reports-dir,attr" yaml:"reports-dir" json:"reports-dir"`

	// ProjectRoot specifies the root directory of the project. All other file names specified in the config file are
	// relative to the root. If not specified, the root is assumed to be the directory of the config file.
	ProjectRoot string `xml:"project-root,attr" yaml:"project-root" json:"project-root"`

	// Suppress warnings
	SilenceWarn bool `xml:"silence-warn,attr" json:"silence-warn" yaml:"silence-warn"`

	// Run and use the escape analysis for analyses that have the option to use the escape analysis results.
	UseEscapeAnalysis bool `xml:"use-escape-analysis,attr" yaml:"use-escape-analysis" json:"use-escape-analysis"`
}

// NewDefault returns an empty default config.
func NewDefault() *Config {
	return &Config{
		sourceFile:         "",
		nocalleereportfile: "",
		DataflowProblems: DataflowProblems{
			PathSensitiveFuncs:        []string{},
			pathSensitiveFuncsRegexes: nil,
		},
		StaticCommandsProblems: nil,
		EscapeConfig:           NewEscapeConfig(),
		PointerConfig:          NewPointerConfig(),
		Options: Options{
			AnalysisProblemOptions: AnalysisProblemOptions{
				UnsafeMaxDepth:           DefaultSafeMaxDepth,
				MaxAlarms:                0,
				MaxEntrypointContextSize: DefaultSafeMaxEntrypointContextSize,
			},
			ReportsDir:          "",
			PkgFilter:           "",
			CoverageFilter:      "",
			ReportSummaries:     false,
			ReportPaths:         false,
			ReportCoverage:      false,
			ReportNoCalleeSites: false,
			LogLevel:            int(InfoLevel),
			SilenceWarn:         false,
		},
	}
}

func unmarshalConfig(b []byte, cfg *Config) error {
	// Strict decoding for yaml config files: will warn user of misconfiguration
	yamlDecoder := yaml.NewDecoder(bytes.NewReader(b))
	yamlDecoder.KnownFields(true)
	errYaml := yamlDecoder.Decode(cfg)
	if errYaml == nil {
		return nil
	}
	errXML := ParseXMLConfigFormat(cfg, b)
	if errXML == nil {
		return nil
	}
	// Strict decoding for json config files: will warn user of misconfiguration
	jsonDecoder := json.NewDecoder(bytes.NewReader(b))
	jsonDecoder.DisallowUnknownFields()
	errJson := jsonDecoder.Decode(cfg)
	if errJson == nil {
		return nil
	}
	return errorMisconfigurationGracefully(errYaml, errXML, errJson)
}

func errorMisconfigurationGracefully(errYaml, errXML, errJson error) error {
	// A list of messages that is likely to appear if the user is using an old configuration file
	oldConfigFingerprints := []string{
		"field unsafe-max-depth not found in type config.Options",
		"field max-alarms not found in type config.Options",
		"field max-alarms not found in type config.Options",
		"field taint-tracking-problems not found in type config.Config",
		"field slicing-problems not found in type config.Config",
		"field dataflow-specs not found in type config.Config",
		"field source-taints-args not found in type config.Options",
		"field field-sensitive not found in type config.DataflowProblems",
		"field skip-interprocedural not found in type config.Options",
	}
	msgUpgrade := "your config follows an outdated format. Please consult documentation and update the config file"
	for _, fingerprint := range oldConfigFingerprints {
		if strings.Contains(errYaml.Error(), fingerprint) {
			return fmt.Errorf("could not parse config file:\n%w\n%s", errYaml, msgUpgrade)
		}
		if strings.Contains(errJson.Error(), fingerprint) {
			return fmt.Errorf("could not parse config file:\n%w\n%s", errJson, msgUpgrade)
		}
	}

	// default behaviour is just to forward the error messages of all unmarshalling attempts
	return fmt.Errorf("could not parse config file, not as yaml: %w,\nnot as xml: %v,\nnot as json: %v\n",
		errYaml, errXML, errJson)
}

// LoadFromFiles loads a full config from configFileName and the config file's
// specified escape config file name, reading the files from disk.
// If the escape config file name is empty, there will be no escape configuration.
func LoadFromFiles(configFileName string) (*Config, error) {
	cfgBytes, err := os.ReadFile(configFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", configFileName, err)
	}

	cfg, err := Load(configFileName, cfgBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create config file: %v", err)
	}

	if len(cfg.EscapeConfigFile) == 0 {
		return cfg, nil
	}

	escFileName := cfg.RelPath(cfg.EscapeConfigFile)
	escBytes, err := os.ReadFile(escFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read escape config file %s: %v", escFileName, err)
	}

	if err := LoadEscape(cfg, escBytes); err != nil {
		return nil, fmt.Errorf("failed to initialize escape config: %v", err)
	}

	return cfg, nil
}

// Load constructs a configuration from a byte slice representing the config file.
//
//gocyclo:ignore
func Load(filename string, configBytes []byte) (*Config, error) {
	// Get absolute path to config. Other files in config will be relative to where the config is.
	pathToConfig := filename
	if !path.IsAbs(filename) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to set absolute path to config: %s", err)
		}
		pathToConfig = filepath.Join(wd, pathToConfig)
	}
	cfg := NewDefault()
	unmarshallingError := unmarshalConfig(configBytes, cfg)
	if unmarshallingError != nil {
		return nil, unmarshallingError
	}
	cfg.sourceFile = filename

	// If the project root is unspecified, then set to the directory of the config file
	if cfg.ProjectRoot == "" {
		cfg.root = path.Dir(pathToConfig)
	} else if !path.IsAbs(cfg.ProjectRoot) {
		// If it's not an absolute path, compute the absolute path
		cfg.root = path.Join(path.Dir(pathToConfig), cfg.ProjectRoot)
	} else {
		cfg.root = cfg.ProjectRoot
	}

	if cfg.ReportPaths || cfg.ReportSummaries || cfg.ReportCoverage || cfg.ReportNoCalleeSites {
		if err := setReportsDir(cfg); err != nil {
			return nil, fmt.Errorf("failed to set reports dir of config with filename %v: %v", pathToConfig, err)
		}
	}

	// If logLevel has not been specified (i.e. it is 0) set the default to Info
	if cfg.LogLevel == 0 {
		cfg.LogLevel = int(InfoLevel)
	}

	// Set the UnsafeMaxDepth default if it is <= 0
	if cfg.UnsafeMaxDepth <= 0 {
		cfg.UnsafeMaxDepth = DefaultSafeMaxDepth
	}

	// a value of 0 indicating the user did not specify
	if cfg.MaxEntrypointContextSize == 0 {
		cfg.MaxEntrypointContextSize = DefaultSafeMaxEntrypointContextSize
	}

	if cfg.PkgFilter != "" {
		r, err := regexp.Compile(cfg.PkgFilter)
		if err == nil {
			cfg.pkgFilterRegex = r
		}
	}

	if cfg.CoverageFilter != "" {
		r, err := regexp.Compile(cfg.CoverageFilter)
		if err == nil {
			cfg.coverageFilterRegex = r
		}
	}

	if len(cfg.PathSensitiveFuncs) > 0 {
		psRegexes := make([]*regexp.Regexp, 0, len(cfg.PathSensitiveFuncs))
		for _, pf := range cfg.PathSensitiveFuncs {
			r, err := regexp.Compile(pf)
			if err != nil {
				continue
			}
			psRegexes = append(psRegexes, r)
		}
		cfg.pathSensitiveFuncsRegexes = psRegexes
	} else {
		cfg.PathSensitiveFuncs = []string{}
	}

	for _, tSpec := range cfg.DataflowProblems.TaintTrackingProblems {
		funcutil.MapInPlace(tSpec.Sanitizers, compileRegexes)
		funcutil.MapInPlace(tSpec.Sinks, compileRegexes)
		funcutil.MapInPlace(tSpec.Sources, compileRegexes)
		funcutil.MapInPlace(tSpec.Validators, compileRegexes)
		funcutil.MapInPlace(tSpec.Filters, compileRegexes)
	}

	for _, sSpec := range cfg.DataflowProblems.SlicingProblems {
		funcutil.MapInPlace(sSpec.BacktracePoints, compileRegexes)
		funcutil.MapInPlace(sSpec.Filters, compileRegexes)
	}

	for i, spec := range cfg.DiodonPassThroughProblems {
		funcutil.MapInPlace(spec.AppFunctions, compileRegexes)
		funcutil.MapInPlace(spec.CoreFunctions, compileRegexes)
		cfg.DiodonPassThroughProblems[i].CoreAllocFunction = compileRegexes(spec.CoreAllocFunction)
		funcutil.MapInPlace(spec.CoreApiFunctions, compileRegexes)
		funcutil.MapInPlace(spec.AppAccessFilters, compileRegexes)
		funcutil.MapInPlace(spec.CoreAllocFilters, compileRegexes)
		funcutil.MapInPlace(spec.NoLeakFunctions, compileRegexes)
	}

	for _, spec := range cfg.ImmutabilityProblems {
		funcutil.MapInPlace(spec.Values, compileRegexes)
		funcutil.MapInPlace(spec.Filters, compileRegexes)
	}

	for i, siSpec := range cfg.SyntacticProblems.StructInitProblems {
		cfg.SyntacticProblems.StructInitProblems[i].Struct = compileRegexes(siSpec.Struct)
		for j, fSpec := range siSpec.FieldsSet {
			siSpec.FieldsSet[j].Value = compileRegexes(fSpec.Value)
		}
		funcutil.MapInPlace(siSpec.Filters, compileRegexes)
	}

	if cfg.PointerConfig == nil {
		cfg.PointerConfig = NewPointerConfig()
	}

	return cfg, cfg.Validate()
}

// LoadEscape adds the escape configuration settings from escapeConfigBytes into c.
func LoadEscape(c *Config, escapeConfigBytes []byte) error {
	data := NewEscapeConfig()
	if c.EscapeConfigFile != "" {
		if err := json.Unmarshal(escapeConfigBytes, &data); err != nil {
			return fmt.Errorf("failed to unmarshal escape config json: %v", err)
		}
	}
	c.EscapeConfig = data

	if c.EscapeConfig.PkgFilter != "" {
		r, err := regexp.Compile(c.EscapeConfig.PkgFilter)
		if err == nil {
			c.EscapeConfig.pkgFilterRegex = r
		}
	}

	for funcName, summaryType := range c.EscapeConfig.Functions {
		if !(summaryType == EscapeBehaviorUnknown || summaryType == EscapeBehaviorNoop ||
			summaryType == EscapeBehaviorSummarize || strings.HasPrefix(summaryType, "reflect:")) {
			return fmt.Errorf("escape summary type for function %s is not recognized: %s", funcName, summaryType)
		}
	}

	return nil
}

func setReportsDir(c *Config) error {
	if c.ReportsDir == "" {
		tmpdir, err := os.MkdirTemp(c.root, "*-report")
		if err != nil {
			return fmt.Errorf("could not create temp dir for reports")
		}
		c.ReportsDir = tmpdir

		if c.ReportNoCalleeSites {
			reportFile, err := os.CreateTemp(c.ReportsDir, "nocalleesites-*.out")
			if err != nil {
				return fmt.Errorf("could not create report file for no callee site")
			}
			c.nocalleereportfile = reportFile.Name()
			reportFile.Close() // the file will be reopened as needed
		}
	} else {
		c.ReportsDir = path.Join(c.root, c.ReportsDir)
		err := os.Mkdir(c.ReportsDir, 0750)
		if err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("could not create directory %s", c.ReportsDir)
			}
		}
	}
	return nil
}

// ReportNoCalleeFile return the file name that will contain the list of locations that have no callee
func (c Config) ReportNoCalleeFile() string {
	return c.nocalleereportfile
}

// Root returns the absolute path to the root directory
func (c Config) Root() string {
	return c.root
}

// RelPath returns the path of the filename path relative to the root
func (c Config) RelPath(filename string) string {
	return path.Join(c.root, filename)
}

// MatchPkgFilter returns true if the package name pkgname matches the package filter set in the config file. If no
// package filter has been set in the config file, the regex will match anything and return true. This function safely
// considers the case where a filter has been specified by the user, but it could not be compiled to a regex. The safe
// case is to check whether the package filter string is a prefix of the pkgname
func (c Config) MatchPkgFilter(pkgname string) bool {
	if c.pkgFilterRegex != nil {
		return c.pkgFilterRegex.MatchString(pkgname)
	} else if c.PkgFilter != "" {
		return strings.HasPrefix(pkgname, c.PkgFilter)
	} else {
		return true
	}
}

// MatchCoverageFilter returns true if the file name matches the coverageFilterRegex, if specified
func (c Config) MatchCoverageFilter(filename string) bool {
	if c.coverageFilterRegex != nil {
		return c.coverageFilterRegex.MatchString(filename)
	} else if c.CoverageFilter != "" {
		return strings.HasPrefix(filename, c.CoverageFilter)
	} else {
		return true
	}
}

// Verbose returns true is the configuration verbosity setting is larger than Info (i.e. Debug or Trace)
func (c Config) Verbose() bool {
	return c.LogLevel >= int(DebugLevel)
}

// ExceedsMaxDepth returns true if the input exceeds the maximum depth parameter of the configuration.
// (this implements the logic for using maximum depth; if the configuration setting is < 0, then this returns false)
func (c Config) ExceedsMaxDepth(d int) bool {
	return c.UnsafeMaxDepth > 0 && d > c.UnsafeMaxDepth
}

// GetTargetMap returns a map from target names to target files
func (c Config) GetTargetMap() map[string][]string {
	targets := map[string][]string{}
	for _, targetSpec := range c.Targets {
		targets[targetSpec.Name] = targetSpec.Files
	}
	return targets
}

// SetOption sets config option value using a string name for the option and a string value.
// Returns the value (as a string) of the previous setting, or an error.
// Settings that can be set using this function:
// - max-alarms
// - unsafe-max-depth
// - max-entrypoint-context-size
func SetOption(c *Config, name, value string) (string, error) {
	switch name {
	case "max-alarms":
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("max-alarms should be an int: %s", value)
		}
		prev := strconv.Itoa(c.MaxAlarms)
		c.MaxAlarms = intValue
		return prev, nil
	case "unsafe-max-depth":
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("unsafe-max-depth should be an int: %s", value)
		}
		prev := strconv.Itoa(c.UnsafeMaxDepth)
		c.UnsafeMaxDepth = intValue
		return prev, nil
	case "max-entrypoint-context-size":
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("max-entrypoint-context-size should be an int: %s", value)
		}
		prev := strconv.Itoa(c.MaxEntrypointContextSize)
		c.MaxEntrypointContextSize = intValue
		return prev, nil
	}
	return "", fmt.Errorf("%s cannot be set by name", name)
}

// OverrideWithAnalysisOptions overwrites the options in the config with the non-default options in the analysis
// problem options. Overwriting is logged at info level.
func OverrideWithAnalysisOptions(l *LogGroup, c *Config, o *AnalysisProblemOptions) {
	if o.MaxAlarms != 0 {
		l.Infof("max-alarms set to %d (using problem's analysis-options)",
			o.MaxAlarms)
		c.MaxAlarms = o.MaxAlarms
	}

	if o.UnsafeMaxDepth != 0 {
		l.Infof("unsafe-max-depth set to %d (using problem's override-analysis-options)",
			o.UnsafeMaxDepth)
		c.UnsafeMaxDepth = o.UnsafeMaxDepth
	}

	if o.MaxEntrypointContextSize != 0 {
		l.Infof("max-entrypoint-context-size set to %d (using problem's override-analysis-options)",
			o.MaxEntrypointContextSize)
		c.MaxEntrypointContextSize = o.MaxEntrypointContextSize
	}
}

// A TaggedSpec is a problem specification that has targets, a tag and a severity.
type TaggedSpec interface {
	// SpecTag returns the tag of the problem
	SpecTag() string
	// SpecTargets returns the targets of the problem
	SpecTargets() []string
	// SpecSeverity returns the severity of the problem
	SpecSeverity() Severity
}

// GetSpecs returns ALL the problems in the configuration that are tagged specs (i.e. have a tag, severity and targets).
func (c Config) GetSpecs() []TaggedSpec {
	var specs []TaggedSpec
	for _, trackingProblem := range c.TaintTrackingProblems {
		specs = append(specs, TaggedSpec(trackingProblem))
	}
	for _, slicingProblem := range c.SlicingProblems {
		specs = append(specs, TaggedSpec(slicingProblem))
	}
	for _, structInitProblem := range c.SyntacticProblems.StructInitProblems {
		specs = append(specs, TaggedSpec(structInitProblem))
	}
	return specs
}
