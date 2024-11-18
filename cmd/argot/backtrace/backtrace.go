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

// Package backtrace implements the front-end to the backtrace analysis.
package backtrace

import (
	"fmt"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// Usage for CLI
const Usage = `Find all the backwards data flows from a program point.
Usage:
  argot backtrace [options] <package path(s)>`

// Run runs the backtrace analysis on flags.
func Run(flags tools.CommonFlags) error {
	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	cfgLog := config.NewLogGroup(cfg)
	cfgLog.Infof(formatutil.Faint("Argot backtrace tool - " + analysis.Version))

	// Override config parameters with command-line parameters
	if flags.Verbose {
		cfgLog.Infof("verbose command line flag overrides config file log-level %d", cfg.LogLevel)
		cfg.LogLevel = int(config.DebugLevel)
		cfgLog = config.NewLogGroup(cfg)
	}
	if flags.Tag != "" {
		cfgLog.Infof("tag specified on command-line, will analyze only problem with tag \"%s\"", flags.Tag)
	}

	overallReport := config.NewReport()
	for targetName, targetFiles := range tools.GetTargets(flags.FlagSet.Args(), flags.Tag, cfg, "backtrace") {
		start := time.Now()
		state, err := analysis.LoadTarget(targetName, targetFiles, cfgLog, cfg, flags.WithTest)
		if err != nil {
			return fmt.Errorf("failed to load state: %s", err)
		}
		result, err := backtrace.Analyze(state)
		if err != nil {
			return fmt.Errorf("analysis failed: %v", err)
		}
		duration := time.Since(start)
		overallReport.Merge(state.Report)
		cfgLog.Infof("")
		cfgLog.Infof("-%s", strings.Repeat("*", 80))
		cfgLog.Infof("Analysis took %3.4f s\n", duration.Seconds())
		cfgLog.Infof("Found traces for %d entrypoints\n", len(result.Traces))
	}
	overallReport.Dump(cfgLog, cfg)
	return nil
}
