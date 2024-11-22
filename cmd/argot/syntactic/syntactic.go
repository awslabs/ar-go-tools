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

package syntactic

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/syntactic/structinit"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"golang.org/x/tools/go/ssa"
)

// Usage is the usage info for the syntactic analyses.
const Usage = ` Perform syntactic checks on your packages.
Usage:
  argot syntactic [options] <package path(s)>
Examples:
  % argot syntactic -config config.yaml package...
`

// Run runs the syntactic analyses.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return err
	}
	c := config.NewState(cfg)

	// Override config parameters with command-line parameters
	if flags.Verbose {
		c.Logger.Infof("verbose command line flag overrides config file log-level %d", c.Config.LogLevel)
		c.Config.LogLevel = int(config.DebugLevel)
		c.Logger = config.NewLogGroup(c.Config)
	}

	if len(c.Config.SyntacticProblems.StructInitProblems) == 0 {
		c.Logger.Warnf("No syntactic problems in config file.")
		return nil
	}

	if flags.Tag != "" {
		c.Logger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}

	failCount := 0
	overallReport := config.NewReport()
	for targetName, targetFiles := range tools.GetTargets(flags.FlagSet.Args(), flags.Tag, cfg, config.SyntacticTool) {
		report, err := runTarget(c, targetName, targetFiles, flags)
		if err != nil {
			c.Logger.Errorf("Analysis for %s failed: %s", targetName, err)
			failCount += 1
		}
		overallReport.Merge(report)
	}
	overallReport.Dump(c)
	if failCount > 0 {
		os.Exit(1)
	}

	return nil
}

func runTarget(
	c *config.State,
	targetName string,
	targetFiles []string,
	flags tools.CommonFlags,
) (*config.ReportInfo, error) {
	loadOptions := loadprogram.Options{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
		Platform:      "",
		PackageConfig: nil,
	}
	state, err := analysis.BuildPointerTarget(c, targetName, targetFiles, loadOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to load target: %v", err)
	}
	c.Logger.Infof("starting struct init analysis...\n")
	res, err := structinit.Analyze(state)
	if err != nil {
		return nil, fmt.Errorf("struct init analysis error: %v", err)
	}
	s, failed := structinit.ReportResults(res)
	c.Logger.Infof(s)
	if failed {
		return state.Report, fmt.Errorf("struct init analysis found problems, inspect logs for more information")
	}
	return state.Report, nil
}
