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
	"github.com/awslabs/ar-go-tools/analysis/syntactic/structinit"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
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
	logger := config.NewLogGroup(cfg)

	// Override config parameters with command-line parameters
	if flags.Verbose {
		logger.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		logger = config.NewLogGroup(cfg)
	}

	if len(cfg.SyntacticProblems.StructInitProblems) == 0 {
		logger.Warnf("No syntactic problems in config file.")
		return nil
	}

	if flags.Tag != "" {
		logger.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}

	failCount := 0
	overallReport := config.NewReport()
	for targetName, targetFiles := range tools.GetTargets(flags.FlagSet.Args(), flags.Tag, cfg, config.SyntacticTool) {
		report, err := runTarget(flags, targetName, targetFiles, logger, cfg)
		if err != nil {
			logger.Errorf("Analysis for %s failed: %s", targetName, err)
			failCount += 1
		}
		overallReport.Merge(report)
	}
	overallReport.Dump(logger, cfg)
	if failCount > 0 {
		os.Exit(1)
	}

	return nil
}

func runTarget(
	flags tools.CommonFlags,
	targetName string,
	targetFiles []string,
	logger *config.LogGroup,
	cfg *config.Config,
) (*config.ReportInfo, error) {

	state, err := analysis.LoadTarget(targetName, targetFiles, logger, cfg, flags.WithTest)
	if err != nil {
		return nil, fmt.Errorf("failed to load target: %v", err)
	}
	logger.Infof("starting struct init analysis...\n")
	res, err := structinit.Analyze(state)
	if err != nil {
		return nil, fmt.Errorf("struct init analysis error: %v", err)
	}
	s, failed := structinit.ReportResults(res)
	logger.Infof(s)
	if failed {
		return state.Report, fmt.Errorf("struct init analysis found problems, inspect logs for more information")
	}
	return state.Report, nil
}
