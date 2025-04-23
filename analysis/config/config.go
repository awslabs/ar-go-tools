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

	"github.com/awslabs/ar-go-tools/analysis/config/analysiscfg"
	"github.com/awslabs/ar-go-tools/analysis/config/specs"
	"github.com/awslabs/ar-go-tools/analysis/scanning"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
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
func LoadGlobal(overrides *CmdLineOverrides) (*Config, error) {
	cfg, err := LoadFromFiles(configFile, overrides)
	if err != nil {
		return nil, fmt.Errorf("failed to load global config file %v: %v", configFile, err)
	}

	return cfg, err
}

// CmdLineOverrides groups all the config file options that can be overridden by command line arguments.
type CmdLineOverrides struct {
	// LogLevel can be overridden (by setting -verbose for example)
	LogLevel int
	// ReportsDir can be overridden (by setting -out <out-folder>)
	ReportsDir string
}

// EscapeConfig holds the options relative to the escape analysis configuration
type EscapeConfig struct {

	// Functions controls behavior override, keyed by .String() (e.g. command-line-arguments.main,
	// (*package.Type).Method, etc.). A value of "summarize" means process normally, "unknown" is
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
func NewPointerConfig() *analysiscfg.PointerConfig {
	return &analysiscfg.PointerConfig{UnsafeNoEffectFunctions: nil}
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

// parsedConfig contains lists of sanitizers, sinks, sources, static commands to identify ...
// To add elements to a config file, add fields to this struct.
// If some field is not defined in the config file, it will be empty/zero in the struct.
// private fields are not populated from a yaml file, but computed after initialization
type parsedConfig struct {
	Options

	sourceFile string

	// nocalleereportfile is a file name in ReportsDir when ReportNoCalleeSites is true
	nocalleereportfile string

	// EscapeConfig contains the escape-analysis specific configuration parameters
	EscapeConfig *EscapeConfig

	// PointerConfig contains the pointer-analysis specific configuration parameters
	PointerConfig *analysiscfg.PointerConfig `yaml:"pointer-config" json:"pointer-config"`

	// StaticCommandsProblems lists the static commands problems
	StaticCommandsProblems []specs.StaticCommandsSpec `yaml:"static-commands-problems" json:"static-commands-problems"`

	SyntacticProblems specs.SyntacticSpecs `yaml:"syntactic-problems" json:"syntactic-problems"`

	// DataflowProblems specifies the dataflow problems to solve in the config
	specs.ParsedDataflowProblems `yaml:"dataflow-problems" json:"dataflow-problems"`

	// Targets specifies the set of targets that may be used in the config
	Targets []specs.TargetSpec
}

// Config is a config that has been parsed and partially validated.
type Config struct {
	parsedConfig

	specs.DataflowProblems

	root string

	// if the PkgFilter is specified
	pkgFilterRegex *regexp.Regexp

	// if the CoverageFilter is specified
	coverageFilterRegex *regexp.Regexp
}

// Options holds the global options for analyses
// embeds AnalysisProblemOptions
type Options struct {
	analysiscfg.ProblemCfg `xml:"analysis-options,attr" yaml:"analysis-options" json:"analysis-options"`

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
	cfg, err := parsedConfig{
		sourceFile:         "",
		nocalleereportfile: "",
		ParsedDataflowProblems: specs.ParsedDataflowProblems{
			PathSensitiveFuncs: []string{},
		},
		StaticCommandsProblems: nil,
		EscapeConfig:           NewEscapeConfig(),
		PointerConfig:          NewPointerConfig(),
		Options: Options{
			ProblemCfg: analysiscfg.ProblemCfg{
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
	}.Compile(nil)
	if err != nil {
		panic("unexpected error: default config doesn't compile")
	}
	return cfg
}

func unmarshalConfig(b []byte, cfg *parsedConfig) error {
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
	return fmt.Errorf("could not parse config file, not as yaml: %w,\nnot as xml: %v,\nnot as json: %v",
		errYaml, errXML, errJson)
}

// LoadFromFiles loads a full config from configFileName and the config file's
// specified escape config file name, reading the files from disk.
// If the escape config file name is empty, there will be no escape configuration.
func LoadFromFiles(configFileName string, overrides *CmdLineOverrides) (*Config, error) {
	cfgBytes, err := os.ReadFile(configFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", configFileName, err)
	}

	cfg, err := Load(configFileName, cfgBytes, overrides)
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
func Load(filename string, configBytes []byte, cmdLineOverrides *CmdLineOverrides) (*Config, error) {
	cfg := &NewDefault().parsedConfig
	unmarshallingError := unmarshalConfig(configBytes, cfg)
	if unmarshallingError != nil {
		return nil, unmarshallingError
	}
	cfg.sourceFile = filename
	return cfg.Compile(cmdLineOverrides)
}

// Compile the config that was parsed into a config to use in the analyses
//
//gocyclo:ignore
func (p parsedConfig) Compile(cmdLineOverrides *CmdLineOverrides) (*Config, error) {
	// Get absolute path to config. Other files in config will be relative to where the config is.
	pathToConfig := p.sourceFile
	if !path.IsAbs(p.sourceFile) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to set absolute path to config: %s", err)
		}
		pathToConfig = filepath.Join(wd, pathToConfig)
	}

	cfg := &Config{parsedConfig: p}
	// If the project root is unspecified, then set to the directory of the config file
	if cfg.ProjectRoot == "" {
		cfg.root = path.Dir(pathToConfig)
	} else if !filepath.IsAbs(cfg.ProjectRoot) {
		// If it's not an absolute path, compute the absolute path
		cfg.root = filepath.Join(path.Dir(pathToConfig), cfg.ProjectRoot)
	} else {
		cfg.root = cfg.ProjectRoot
	}

	if cfg.ReportPaths || cfg.ReportSummaries || cfg.ReportCoverage || cfg.ReportNoCalleeSites {
		if err := setReportsDir(cfg, cmdLineOverrides); err != nil {
			return nil, fmt.Errorf("failed to set reports dir of config with filename %v: %v", pathToConfig, err)
		}
	}

	// If logLevel has not been specified (i.e. it is 0) set the default to Info
	if cfg.LogLevel == 0 {
		cfg.LogLevel = int(InfoLevel)
	}

	// is the log-level is overridden on the cmd line, set it
	if cmdLineOverrides != nil && cmdLineOverrides.LogLevel > 0 {
		cfg.LogLevel = cmdLineOverrides.LogLevel
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

	dp, err := cfg.ParsedDataflowProblems.Compile()
	if err != nil {
		return cfg, err
	}
	cfg.DataflowProblems = dp

	for _, tSpec := range cfg.ParsedDataflowProblems.TaintTrackingProblems {
		funcutil.MapInPlace(tSpec.Sanitizers, specs.CompileRegexes)
		funcutil.MapInPlace(tSpec.Sinks, specs.CompileRegexes)
		funcutil.MapInPlace(tSpec.Sources, specs.CompileRegexes)
		funcutil.MapInPlace(tSpec.Validators, specs.CompileRegexes)
		funcutil.MapInPlace(tSpec.Filters, specs.CompileRegexes)
	}

	for _, sSpec := range cfg.ParsedDataflowProblems.SlicingProblems {
		funcutil.MapInPlace(sSpec.BacktracePoints, specs.CompileRegexes)
		funcutil.MapInPlace(sSpec.Filters, specs.CompileRegexes)
	}

	for i, siSpec := range cfg.SyntacticProblems.StructInitProblems {
		cfg.SyntacticProblems.StructInitProblems[i].Struct = specs.CompileRegexes(siSpec.Struct)
		for j, fSpec := range siSpec.FieldsSet {
			siSpec.FieldsSet[j].Value = specs.CompileRegexes(fSpec.Value)
		}
		funcutil.MapInPlace(siSpec.Filters, specs.CompileRegexes)
		funcutil.MapInPlace(siSpec.MustReinits, specs.CompileRegexes)
	}

	for i, ccSpec := range cfg.SyntacticProblems.CondCheckSpecs {
		for j, callSpec := range ccSpec.Call {
			cfg.SyntacticProblems.CondCheckSpecs[i].Call[j] = specs.CompileRegexes(callSpec)
		}
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

func setReportsDir(c *Config, cmdLineOverride *CmdLineOverrides) error {
	if cmdLineOverride != nil && cmdLineOverride.ReportsDir != "" {
		err := os.Mkdir(cmdLineOverride.ReportsDir, 0750)
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("could not create reports dir passed on commandline, and it doesn't exist")
		}
		// no attempt is made to check the path is absolute or needs to be relative to root
		c.ReportsDir = cmdLineOverride.ReportsDir
		return nil
	}

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
	} else if !filepath.IsAbs(c.ReportsDir) {
		c.ReportsDir = filepath.Join(c.root, c.ReportsDir)
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

// RelPath returns the path of the filename joined to the root
func (c Config) RelPath(filename string) string {
	return filepath.Join(c.root, filename)
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

// TargetInfo is the information needed to build the target
type TargetInfo struct {
	// Patterns in the target
	Patterns []string
	// Platform of the target
	Platform string
	// UseProgramTransforms for the target
	UseProgramTransforms bool
	// ReflectValueCallInstances
	ReflectValueCallInstances []specs.ParsedCodeIdentifier
}

// GetTargetMap returns a map from target names to target files
func (c Config) GetTargetMap() map[string]TargetInfo {
	targets := map[string]TargetInfo{}
	for _, targetSpec := range c.Targets {
		reflectValueCallInstances := []specs.ParsedCodeIdentifier{}
		for _, r := range targetSpec.ReflectValueCallInstances {
			reflectValueCallInstances = append(reflectValueCallInstances, specs.CompileRegexes(r))
		}
		targets[targetSpec.Name] = TargetInfo{
			Patterns:                  targetSpec.Files,
			Platform:                  targetSpec.Platform,
			UseProgramTransforms:      targetSpec.UseProgramTransforms,
			ReflectValueCallInstances: reflectValueCallInstances,
		}
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
func OverrideWithAnalysisOptions(l *LogGroup, c *Config, o analysiscfg.ProblemCfg) {
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
	SpecSeverity() analysiscfg.Severity
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

// IsPathSensitiveFunc returns true if funcName matches any regex in c.Options.PathSensitiveFuncs.
func (c Config) IsPathSensitiveFunc(funcName string) bool {
	for _, psfr := range c.PathSensitiveFuncsRegexes {
		if psfr == nil {
			continue
		}
		if psfr.MatchString(funcName) {
			return true
		}
	}

	return false
}

// IsSomeSource returns true if the code identifier matches any source in the config
func (c Config) IsSomeSource(p *pointer.Result, code scanning.SsaCode) bool {
	for _, ttp := range c.DataflowProblems.TaintTrackingProblems {
		if ttp.IsSource(p, code) {
			return true
		}
	}
	return false
}

// IsSomeSink returns true if the code identifier matches any sink in the config
func (c Config) IsSomeSink(p *pointer.Result, code scanning.SsaCode) bool {
	for _, ttp := range c.DataflowProblems.TaintTrackingProblems {
		if ttp.IsSink(p, code) {
			return true
		}
	}
	return false
}

// IsSomeSanitizer returns true if the code identifier matches any sanitizer in the config
func (c Config) IsSomeSanitizer(p *pointer.Result, code scanning.SsaCode) bool {
	for _, ttp := range c.DataflowProblems.TaintTrackingProblems {
		if ttp.IsSanitizer(p, code) {
			return true
		}
	}
	return false
}

// IsSomeValidator returns true if the code identifier matches any validator in the config
func (c Config) IsSomeValidator(p *pointer.Result, code scanning.SsaCode) bool {
	for _, ttp := range c.DataflowProblems.TaintTrackingProblems {
		if ttp.IsValidator(p, code) {
			return true
		}
	}
	return false
}

// IsSomeBacktracePoint returns true if the code identifier matches any backtrace point in the slicing problems
func (c Config) IsSomeBacktracePoint(p *pointer.Result, code scanning.SsaCode) bool {
	for _, ttp := range c.DataflowProblems.SlicingProblems {
		if ttp.IsBacktracePoint(p, code) {
			return true
		}
	}
	return false
}
