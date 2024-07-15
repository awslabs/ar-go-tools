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
	"regexp"
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

	// DataFlowSpecs is a path to a json file that contains the data flows specs for the interfaces in the dataflow
	// analyses
	DataflowSpecs []string `yaml:"dataflow-specs" json:"dataflow-specs"`

	// if the PkgFilter is specified
	pkgFilterRegex *regexp.Regexp

	// if the CoverageFilter is specified
	coverageFilterRegex *regexp.Regexp

	// EscapeConfig contains the escape-analysis specific configuration parameters
	EscapeConfig *EscapeConfig

	// PointerConfig contains the pointer-analysis specific configuration parameters
	PointerConfig *PointerConfig `yaml:"pointer-config" json:"pointer-config"`

	// TaintTrackingProblems lists the taint tracking specifications
	TaintTrackingProblems []TaintSpec `yaml:"taint-tracking-problems" json:"taint-tracking-problems"`

	// SlicingProblems lists the program slicing specifications
	SlicingProblems []SlicingSpec `yaml:"slicing-problems" json:"slicing-problems"`

	// StaticCommandsProblems lists the static commands problems
	StaticCommandsProblems []StaticCommandsSpec `yaml:"static-commands-problems" json:"static-commands-problems"`
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

// TaintSpec contains code identifiers that identify a specific taint tracking problem
type TaintSpec struct {
	// Sanitizers is the list of sanitizers for the taint analysis
	Sanitizers []CodeIdentifier

	// Validators is the list of validators for the dataflow analyses
	Validators []CodeIdentifier

	// Sinks is the list of sinks for the taint analysis
	Sinks []CodeIdentifier

	// Sources is the list of sources for the taint analysis
	Sources []CodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []CodeIdentifier

	// FailOnImplicitFlow indicates whether the taint analysis should fail when tainted data implicitly changes
	// the control flow of a program. This should be set to false when proving a data flow property,
	// and set to true when proving an information flow property.
	FailOnImplicitFlow bool `yaml:"fail-on-implicit-flow" json:"fail-on-implicit-flow"`
}

// SlicingSpec contains code identifiers that identify a specific program slicing / backwards dataflow analysis spec.
type SlicingSpec struct {
	// BacktracePoints is the list of identifiers to be considered as entrypoint functions for the backwards
	// dataflow analysis.
	BacktracePoints []CodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []CodeIdentifier
}

// StaticCommandsSpec contains code identifiers for the problem of identifying which commands are static
type StaticCommandsSpec struct {
	// StaticCommands is the list of identifiers to be considered as command execution for the static commands analysis
	// (not used)
	StaticCommands []CodeIdentifier `yaml:"static-commands" json:"static-commands"`
}

// Options holds the global options for analyses
type Options struct {
	// Path to a JSON file that has the escape configuration (allow/blocklist)
	EscapeConfigFile string `xml:"escape-config,attr" yaml:"escape-config" json:"escape-config"`

	// CoverageFilter can be used to filter which packages will be reported in the coverage. If non-empty,
	// coverage will only for those packages that match CoverageFilter
	CoverageFilter string `xml:"coverage-filter,attr" yaml:"coverage-filter" json:"coverage-filter"`

	// Loglevel controls the verbosity of the tool
	LogLevel int `xml:"log-level,attr" yaml:"log-level" json:"log-level"`

	// MaxAlarms sets a limit for the number of alarms reported by an analysis.  If MaxAlarms > 0, then at most
	// MaxAlarms will be reported. Otherwise, if MaxAlarms <= 0, it is ignored.
	//
	// This setting does not affect soundness, since event with max-alarms:1, at least one path will be reported if
	// there is some potential alarm-causing result.
	MaxAlarms int `xml:"max-alarms,attr" yaml:"max-alarms" json:"max-alarms"`

	// MaxEntrypointContextSize sets the maximum context (call stack) size used when searching for entry points with context.
	// This only impacts precision of the returned results.
	//
	// If MaxEntrypointContextSize is < 0, it is ignored.
	// If MaxEntrypointContextSize is 0 is specified by the user, the value is ignored, and a default internal value is used.
	// If MaxEntrypointContextSize is > 0, then the limit in the callstack size for the context is used.
	MaxEntrypointContextSize int `xml:"max-entrypoint-context-size,attr" yaml:"max-entrypoint-context-size" json:"max-entrypoint-context-size"`

	// PathSensitive is a boolean indicating whether the analysis should be run with access path sensitivity on
	// (will change to include more filtering in the future)
	//
	// Note that the configuration option name is "field-sensitive" because this is the name that will be more
	// recognizable for users.
	//
	// TODO deprecate since this case is covered by `"field-sensitive-funcs": [".*"]`?
	PathSensitive bool `xml:"field-sensitive" yaml:"field-sensitive" json:"field-sensitive"`

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

	// PathSensitiveFuncs is a list of regexes indicating which functions should be path-sensitive.
	// This allows the analysis to scale yet still maintain a degree of precision where it matters.
	PathSensitiveFuncs []string `xml:"field-sensitive-funcs" yaml:"field-sensitive-funcs" json:"field-sensitive-funcs"`

	// pathSensitiveFuncsRegexes is a list of compiled regexes corresponding to PathSensitiveFuncs
	pathSensitiveFuncsRegexes []*regexp.Regexp

	// SkipInterprocedural can be set to true to skip the interprocedural (inter-procedural analysis) step
	SkipInterprocedural bool `xml:"skip-interprocedural,attr" yaml:"skip-interprocedural" json:"skip-interprocedural"`

	// Suppress warnings
	SilenceWarn bool `xml:"silence-warn,attr" json:"silence-warn" yaml:"silence-warn"`

	// SourceTaintsArgs specifies whether calls to a source function also taints the argument. This is usually not
	// the case, but might be useful for some users or for source functions that do not return anything.
	SourceTaintsArgs bool `xml:"source-taints-args,attr" yaml:"source-taints-args" json:"source-taints-args"`

	// SummarizeOnDemand specifies whether the graph should build summaries on-demand instead of all at once
	SummarizeOnDemand bool `xml:"summarize-on-demand,attr" yaml:"summarize-on-demand" json:"summarize-on-demand"`

	// UnsafeMaxDepth sets a limit for the number of function call depth explored during the analysis.
	// The default is -1, and any value less or equal than 0 is safe: the analysis will be sound and explore call depth
	// without bounds.
	//
	// Setting UnsafeMaxDepth to a limit larger than 0 will yield unsound results, but can be useful to use the tool
	// as a checking mechanism. Limiting the call depth will usually yield fewer false positives.
	UnsafeMaxDepth int `xml:"unsafe-max-depth,attr" yaml:"unsafe-max-depth" json:"unsafe-max-depth"`

	// UnsafeIgnoreNonSummarized allows the analysis to ignore when the summary of a function has not been built in
	// the first analysis phase. This is only for experimentation, since the results may be unsound.
	// This has no effect when SummarizeOnDemand is true.
	UnsafeIgnoreNonSummarized bool `xml:"unsafeIgnoreNonSummarized,attr" yaml:"unsafe-ignore-non-summarized" json:"unsafe-ignore-non-summarized"`

	// Run and use the escape analysis for analyses that have the option to use the escape analysis results.
	UseEscapeAnalysis bool `xml:"use-escape-analysis,attr" yaml:"use-escape-analysis" json:"use-escape-analysis"`
}

// NewDefault returns an empty default config.
func NewDefault() *Config {
	return &Config{
		sourceFile:             "",
		nocalleereportfile:     "",
		TaintTrackingProblems:  nil,
		SlicingProblems:        nil,
		StaticCommandsProblems: nil,
		DataflowSpecs:          []string{},
		EscapeConfig:           NewEscapeConfig(),
		PointerConfig:          NewPointerConfig(),
		Options: Options{
			ReportsDir:                "",
			PkgFilter:                 "",
			SkipInterprocedural:       false,
			CoverageFilter:            "",
			ReportSummaries:           false,
			ReportPaths:               false,
			ReportCoverage:            false,
			ReportNoCalleeSites:       false,
			UnsafeMaxDepth:            DefaultSafeMaxDepth,
			MaxAlarms:                 0,
			MaxEntrypointContextSize:  DefaultSafeMaxEntrypointContextSize,
			LogLevel:                  int(InfoLevel),
			SilenceWarn:               false,
			SourceTaintsArgs:          false,
			UnsafeIgnoreNonSummarized: false,
			PathSensitive:             false,
			PathSensitiveFuncs:        []string{},
			pathSensitiveFuncsRegexes: nil,
		},
	}
}

func unmarshalConfig(b []byte, cfg *Config) error {
	// Strict decoding for json config files: will warn user of misconfiguration
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
		return errJson
	}
	return fmt.Errorf("could not unmarshal config file, not as yaml: %w, not as xml: %v, not as json: %v",
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
	cfg := NewDefault()
	unmarshallingError := unmarshalConfig(configBytes, cfg)
	if unmarshallingError != nil {
		return nil, unmarshallingError
	}
	cfg.sourceFile = filename

	if cfg.ReportPaths || cfg.ReportSummaries || cfg.ReportCoverage || cfg.ReportNoCalleeSites {
		if err := setReportsDir(cfg, filename); err != nil {
			return nil, fmt.Errorf("failed to set reports dir of config with filename %v: %v", filename, err)
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

	if len(cfg.Options.PathSensitiveFuncs) > 0 {
		psRegexes := make([]*regexp.Regexp, 0, len(cfg.Options.PathSensitiveFuncs))
		for _, pf := range cfg.Options.PathSensitiveFuncs {
			r, err := regexp.Compile(pf)
			if err != nil {
				continue
			}
			psRegexes = append(psRegexes, r)
		}
		cfg.Options.pathSensitiveFuncsRegexes = psRegexes
	} else {
		cfg.Options.PathSensitiveFuncs = []string{}
	}

	for _, tSpec := range cfg.TaintTrackingProblems {
		funcutil.Iter(tSpec.Sanitizers, compileRegexes)
		funcutil.Iter(tSpec.Sinks, compileRegexes)
		funcutil.Iter(tSpec.Sources, compileRegexes)
		funcutil.Iter(tSpec.Validators, compileRegexes)
		funcutil.Iter(tSpec.Filters, compileRegexes)
	}

	for _, sSpec := range cfg.SlicingProblems {
		funcutil.Iter(sSpec.BacktracePoints, compileRegexes)
		funcutil.Iter(sSpec.Filters, compileRegexes)
	}

	for _, stSpec := range cfg.StaticCommandsProblems {
		funcutil.Iter(stSpec.StaticCommands, compileRegexes)
	}

	if cfg.PointerConfig == nil {
		cfg.PointerConfig = NewPointerConfig()
	}

	return cfg, nil
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

func setReportsDir(c *Config, filename string) error {
	if c.ReportsDir == "" {
		tmpdir, err := os.MkdirTemp(path.Dir(filename), "*-report")
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

// RelPath returns filename path relative to the config source file
func (c Config) RelPath(filename string) string {
	return path.Join(path.Dir(c.sourceFile), filename)
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

// IsPathSensitiveFunc returns true if funcName matches any regex in c.Options.PathSensitiveFuncs.
func (c Config) IsPathSensitiveFunc(funcName string) bool {
	for _, psfr := range c.Options.pathSensitiveFuncsRegexes {
		if psfr == nil {
			continue
		}
		if psfr.MatchString(funcName) {
			return true
		}
	}

	return false
}

// Below are functions used to query the configuration on specific facts

func (c Config) isSomeTaintSpecCid(cid CodeIdentifier, f func(t TaintSpec, cid CodeIdentifier) bool) bool {
	for _, x := range c.TaintTrackingProblems {
		if f(x, cid) {
			return true
		}
	}
	return false
}

// IsSomeSource returns true if the code identifier matches any source in the config
func (c Config) IsSomeSource(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSource(cid2) })
}

// IsSomeSink returns true if the code identifier matches any sink in the config
func (c Config) IsSomeSink(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSink(cid2) })
}

// IsSomeSanitizer returns true if the code identifier matches any sanitizer in the config
func (c Config) IsSomeSanitizer(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSanitizer(cid2) })
}

// IsSomeValidator returns true if the code identifier matches any validator in the config
func (c Config) IsSomeValidator(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsValidator(cid2) })
}

// IsSomeBacktracePoint returns true if the code identifier matches any backtrace point in the slicing problems
func (c Config) IsSomeBacktracePoint(cid CodeIdentifier) bool {
	for _, ss := range c.SlicingProblems {
		if ss.IsBacktracePoint(cid) {
			return true
		}
	}
	return false
}

// IsSource returns true if the code identifier matches a source specification in the config file
func (ts TaintSpec) IsSource(cid CodeIdentifier) bool {
	b := ExistsCid(ts.Sources, cid.equalOnNonEmptyFields)
	return b
}

// IsSink returns true if the code identifier matches a sink specification in the config file
func (ts TaintSpec) IsSink(cid CodeIdentifier) bool {
	return ExistsCid(ts.Sinks, cid.equalOnNonEmptyFields)
}

// IsSanitizer returns true if the code identifier matches a sanitizer specification in the config file
func (ts TaintSpec) IsSanitizer(cid CodeIdentifier) bool {
	return ExistsCid(ts.Sanitizers, cid.equalOnNonEmptyFields)
}

// IsValidator returns true if the code identifier matches a validator specification in the config file
func (ts TaintSpec) IsValidator(cid CodeIdentifier) bool {
	return ExistsCid(ts.Validators, cid.equalOnNonEmptyFields)
}

// IsStaticCommand returns true if the code identifier matches a static command specification in the config file
func (scs StaticCommandsSpec) IsStaticCommand(cid CodeIdentifier) bool {
	return ExistsCid(scs.StaticCommands, cid.equalOnNonEmptyFields)
}

// IsBacktracePoint returns true if the code identifier matches a backtrace point according to the SlicingSpec
func (ss SlicingSpec) IsBacktracePoint(cid CodeIdentifier) bool {
	return ExistsCid(ss.BacktracePoints, cid.equalOnNonEmptyFields)
}

// Verbose returns true is the configuration verbosity setting is larger than Info (i.e. Debug or Trace)
func (c Config) Verbose() bool {
	return c.LogLevel >= int(DebugLevel)
}

// ExceedsMaxDepth returns true if the input exceeds the maximum depth parameter of the configuration.
// (this implements the logic for using maximum depth; if the configuration setting is < 0, then this returns false)
func (c Config) ExceedsMaxDepth(d int) bool {
	return !(c.UnsafeMaxDepth <= 0) && d > c.UnsafeMaxDepth
}
