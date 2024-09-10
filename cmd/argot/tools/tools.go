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

// Package tools contains utility types and functions for Argot tool frontends.
package tools

import (
	"flag"
	"fmt"
	"go/build"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"golang.org/x/tools/go/buildutil"
)

// UnparsedCommonFlags represents an unparsed CLI sub-command flags.
type UnparsedCommonFlags struct {
	FlagSet    *flag.FlagSet
	ConfigPath *string
	Verbose    *bool
	WithTest   *bool
}

// NewUnparsedCommonFlags returns an unparsed flag set with a given name.
// This is useful for creating sub-commands that have the flags -config,
// -verbose, -with-test, and -build-tags but need other flags in addition.
func NewUnparsedCommonFlags(name string) UnparsedCommonFlags {
	cmd := flag.NewFlagSet(name, flag.ExitOnError)
	configPath := cmd.String("config", "", "config file path for analysis")
	verbose := cmd.Bool("verbose", false, "verbose printing on standard output")
	withTest := cmd.Bool("with-test", false, "load tests during analysis")
	cmd.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "build-tags", buildutil.TagsFlagDoc)
	return UnparsedCommonFlags{
		FlagSet:    cmd,
		ConfigPath: configPath,
		Verbose:    verbose,
		WithTest:   withTest,
	}
}

// CommonFlags represents a parsed CLI sub-command flags.
// E.g., for the command `argot taint ...`, "taint" is the sub-command.
// This is only for sub-commands that have common flags
// (config, verbose, with-test, and build-tags).
type CommonFlags struct {
	FlagSet    *flag.FlagSet
	ConfigPath string
	Verbose    bool
	WithTest   bool
}

// NewCommonFlags returns a parsed flag set with a given name.
// Returns an error if args are invalid.
// Prints cmdUsage along with flag docs as the --help message.
func NewCommonFlags(name string, args []string, cmdUsage string) (CommonFlags, error) {
	flags := NewUnparsedCommonFlags(name)
	SetUsage(flags.FlagSet, cmdUsage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return CommonFlags{}, fmt.Errorf("failed to parse command %s with args %v: %v", name, args, err)
	}

	return CommonFlags{
		FlagSet:    flags.FlagSet,
		ConfigPath: *flags.ConfigPath,
		Verbose:    *flags.Verbose,
		WithTest:   *flags.WithTest,
	}, nil
}

// SetUsage sets cmd's usage (for --help flag) to output the string cmdUsage
// followed by each flag's documentation.
func SetUsage(cmd *flag.FlagSet, cmdUsage string) {
	cmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", cmdUsage)
		fmt.Fprintf(os.Stderr, "Options:\n")
		cmd.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  %s: %s (default: %q)\n", f.Name, f.Usage, f.DefValue)
		})
	}
}

// ExcludePaths represents filepaths to exclude.
type ExcludePaths []string

func (e *ExcludePaths) String() string {
	if e == nil {
		return "[]"
	}
	return fmt.Sprintf("%v", []string(*e))
}

// Set adds value to e.
// This method satisfies the flag.Value interface.
func (e *ExcludePaths) Set(value string) error {
	*e = append(*e, value)
	return nil
}

// LoadConfig loads the config file from configPath.
func LoadConfig(configPath string) (*config.Config, error) {
	if configPath == "" {
		return nil, fmt.Errorf("file not specified")
	}
	config.SetGlobalConfig(configPath)
	cfg, err := config.LoadGlobal()
	if err != nil {
		return nil, fmt.Errorf("failed to load config file %s: %v", configPath, err)
	}

	return cfg, nil
}
