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

// Package defers implements the frontend to the analysis to detect unbounded defers.
package defers

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// Usage for defers tool.
const Usage = `Find unbounded defer statements.

Usage:
  argot defer package...
  argot defer source.go
  argot defer source1.go source2.go

prefix with GOOS and/or GOARCH to analyze a different architecture:
  GOOS=windows GOARCH=amd64 argot defer main_windows.go

Use the -help flag to display the options.

Use -verbose for debugging output.

Examples:
$ argot defer hello.go
`

// Run runs the defer analysis with args.
func Run(args []string, verbose bool) error {
	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     false,
		ApplyRewrites: true,
	}
	cfg := config.NewDefault()
	if verbose {
		cfg.LogLevel = int(config.TraceLevel)
	}
	c := config.NewState(cfg, "", args, loadOptions)
	target, err := loadprogram.NewState(c).Value()
	if err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

	defers.AnalyzeProgram(target, config.NewLogGroup(cfg))

	return nil
}
