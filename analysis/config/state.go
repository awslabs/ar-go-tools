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
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// PkgLoadMode is the default loading mode in the analyses. We load all possible information
const PkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

// LoadOptions combines all the options that are used when loading programs.
type LoadOptions struct {
	// BuildMode is the mode used when creating the SSA from the packages.
	BuildMode ssa.BuilderMode
	// LoadTests is a flag indicating whether tests should be loaded with the program.
	LoadTests bool
	// ApplyRewrites is a flag indicating whether the standard source rewrites should be applied.
	ApplyRewrites bool
	// Platform indicates which platform the analysis is being performed on (sets GOOS in env).
	Platform string
	// PackageConfig is the options passed to packages.Load.
	// The GOOS  in the Env of the packageConfig is overridden by the Platform when Platform is set.
	PackageConfig *packages.Config
}

// Configurer groups a config and a logger. All "state" structs should implement this.
type Configurer interface {
	GetConfig() *Config
	GetLogger() *LogGroup
}

// ConfiguredLogger is the simplest Configurer
type ConfiguredLogger struct {
	Config *Config
	Logger *LogGroup
}

// GetConfig returns the config of the state
func (s ConfiguredLogger) GetConfig() *Config {
	return s.Config
}

// GetLogger returns the logger of the state
func (s ConfiguredLogger) GetLogger() *LogGroup {
	return s.Logger
}

// A State for config is a config with a logger.
type State struct {
	Config   *Config
	Logger   *LogGroup
	Target   string
	Patterns []string
	Options  LoadOptions
}

// NewState returns a new state from a config by adding a logger built from that config.
func NewState(c *Config, target string, patterns []string, options LoadOptions) *State {
	return &State{
		Config:   c,
		Logger:   NewLogGroup(c),
		Target:   target,
		Patterns: patterns,
		Options:  options,
	}
}

// GetConfig returns the config of the state
func (s *State) GetConfig() *Config {
	return s.Config
}

// GetLogger returns the logger of the state
func (s *State) GetLogger() *LogGroup {
	return s.Logger
}
