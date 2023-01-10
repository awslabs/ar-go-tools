// Package config provides a simple way to manage configuration files.
// Use Load(filename) to load a configuration from a specific filename.
// Use SetGlobalConfig(filename) to set filename as the global config, and
// then LoadGlobal() to load the global config.
// A config file should be in yaml format. The top-level fields can be any of
// the fields defined in the Config struct type. The other fields  are defined
// by the types of the fields of Config and nested struct types.
// For example, a valid config file is as follows:
// ```
// sinks::
//   - package: fmt
//     method: Printf
//
// sources:
//   - method: Read
//
// ```
// (note the use of lowercase)
package config

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"gopkg.in/yaml.v3"
	"os"
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
	return Load(configFile)
}

// Config contains lists of sanitizers, sinks, sources, static commands to identify ...
// To add elements to a config file, add fields to this struct.
// If some field is not defined in the config file, it will be empty/zero in the struct.
type Config struct {
	Sanitizers          []CodeIdentifier
	Sinks               []CodeIdentifier
	Sources             []CodeIdentifier
	StaticCommands      []CodeIdentifier
	PkgPrefix           string
	CoverageFile        string
	Coverage            string
	SkipInterprocedural bool
	OutputSummaries     bool
}

// Load reads a configuration from a file
func Load(filename string) (*Config, error) {
	config := Config{}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config file: %w", err)
	}

	functional.Iter(config.Sanitizers, CompileRegexes)
	functional.Iter(config.Sinks, CompileRegexes)
	functional.Iter(config.Sources, CompileRegexes)
	functional.Iter(config.StaticCommands, CompileRegexes)

	return &config, nil
}

// Below are functions used to query the configuration on specific facts

func (c Config) IsSource(cid CodeIdentifier) bool {
	b := ExistsCid(c.Sources, cid.equalOnNonEmptyFields)
	return b
}

func (c Config) IsSink(cid CodeIdentifier) bool {
	return ExistsCid(c.Sinks, cid.equalOnNonEmptyFields)
}

func (c Config) IsSanitizer(cid CodeIdentifier) bool {
	return ExistsCid(c.Sanitizers, cid.equalOnNonEmptyFields)
}

func (c Config) IsStaticCommand(cid CodeIdentifier) bool {
	return ExistsCid(c.StaticCommands, cid.equalOnNonEmptyFields)
}
