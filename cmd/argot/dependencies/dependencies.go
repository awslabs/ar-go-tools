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

// Package dependencies implements the frontend to the dependencies analysis.
package dependencies

import (
	"flag"
	"fmt"
	"go/build"
	"io"
	"log"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dependencies"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

const usage = `Analyze your Go packages.

Usage:
  argot dependencies package...
  argot dependencies source.go

Use the -help flag to display the options.

Examples:
% argot dependencies hello.go
`

// Flags represents the flags for the dependencies sub-command.
type Flags struct {
	configPath     string
	coverPath      string
	graphPath      string
	csvPath        string
	outputJson     bool
	includeStdlib  bool
	usageThreshold float64
	locThreshold   int
	withTest       bool
	flagSet        *flag.FlagSet
}

// NewFlags creates a new parsed dependencies sub-command from args.
// Returns an error if args is invalid.
func NewFlags(args []string) (Flags, error) {
	cmd := flag.NewFlagSet("dependencies", flag.ExitOnError)
	configPath := cmd.String("config", "", "configuration file path")
	coverPath := cmd.String("cover", "", "output coverage file path")
	graphPath := cmd.String("graph", "", "output graphviz file path")
	csvPath := cmd.String("csv", "", "output results in csv")
	outputJson := cmd.Bool("json", false, "output results as JSON")
	includeStdlib := cmd.Bool("stdlib", false, "include standard library packages")
	usageThreshold := cmd.Float64("usage", 10.0, "usage threshold below which warning produced")
	locThreshold := cmd.Int("loc", 100, "loc threshold under which a warning is produced if usage is also below percentage")
	withTest := cmd.Bool("with-test", false, "also include tests in dependency analysis")
	cmd.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	tools.SetUsage(cmd, usage)
	if err := cmd.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse dependencies command with args %v: %v", args, err)
	}

	return Flags{
		configPath:     *configPath,
		coverPath:      *coverPath,
		graphPath:      *graphPath,
		csvPath:        *csvPath,
		outputJson:     *outputJson,
		includeStdlib:  *includeStdlib,
		usageThreshold: *usageThreshold,
		locThreshold:   *locThreshold,
		withTest:       *withTest,
		flagSet:        cmd,
	}, nil
}

// Run runs the analysis.
func Run(flags Flags) error {
	var err error
	var cfg *config.Config
	if flags.configPath == "" {
		cfg = config.NewDefault()
	} else {
		cfg, err = config.LoadFromFiles(flags.configPath)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %s", flags.configPath, err)
		}
	}

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.withTest,
		ApplyRewrites: true,
	}
	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: flags.flagSet.Args(),
		Tool:        config.DependenciesTool,
	})
	if err != nil {
		return fmt.Errorf("failed to get dependencies targets: %s", err)
	}
	for targetName, targetFiles := range actualTargets {
		err = runTarget(cfg, targetName, targetFiles, loadOptions, flags)
		if err != nil {
			return err
		}
	}
	return nil
}

func runTarget(c *config.Config, name string, files []string, options config.LoadOptions, flags Flags) error {
	state, err := loadprogram.NewState(config.NewState(c, name, files, options)).Value()
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer state: %s", err)
	}

	state.Logger.Infof(formatutil.Faint("Analyzing"))

	var coverageWriter io.WriteCloser
	var csvWriter io.WriteCloser

	if flags.coverPath != "" {
		coverageWriter, err = os.OpenFile(flags.coverPath, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer coverageWriter.Close()

		coverageWriter.Write([]byte("mode: set\n"))
	}

	if flags.csvPath != "" {
		csvWriter, err = os.OpenFile(flags.csvPath, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer csvWriter.Close()
		csvWriter.Write([]byte("dependency,direct?, loc used,loc total,% used\n"))
	}

	dependencyGraph := dependencies.DependencyAnalysis(state, dependencies.DependencyConfigs{
		JsonFlag:       flags.outputJson,
		IncludeStdlib:  flags.includeStdlib,
		CoverageFile:   coverageWriter,
		CsvFile:        csvWriter,
		UsageThreshold: flags.usageThreshold,
		LocThreshold:   flags.locThreshold,
		ComputeGraph:   true,
	})

	if flags.coverPath != "" {
		state.Logger.Infof("Coverage written in: %s", flags.coverPath)
	}

	if dependencyGraph == nil {
		return fmt.Errorf("failed to generate dependency graph")
	}

	state.Logger.Debugf("Checking cycles in dependency graph")
	if dependencyGraph.Cycles() {
		state.Logger.Errorf("FOUND CYCLES IN THE DEPENDENCY GRAPH")
	}

	if flags.graphPath != "" {
		state.Logger.Infof("Writing Graphviz in: %s", flags.graphPath)
		dependencyGraph.DumpAsGraphviz(flags.graphPath, flags.includeStdlib)
	}

	return nil
}
