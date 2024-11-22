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

// Package render implements a tool for rendering various "visualizations" of Go programs.
// -cgout Given a path for a .dot file, generates the callgraph of the program in that file.
// -ssaout Given a path for a folder, generates subfolders with files containing
// the ssa representation of each package in that file.
package render

import (
	"fmt"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

const usage = `Render callgraphs or ssa representation of your packages.
Usage:
  argot render [options] <package path(s)>
Examples:
Render a callgraph computed using pointer analysis
  % argot render -analysis pointer  -cgout example.dot package...
Print out all the packages in SSA form
  % argot render -ssaout tmpSsa package...
`

// Flags represents the parsed render sub-command flags.
type Flags struct {
	tools.CommonFlags
	cgAnalysis string
	cgOut      string
	htmlOut    string
	dfOut      string
	ssaOut     string
}

// NewFlags returns the parsed render sub-command flags from args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("render")
	cgAnalysis := flags.FlagSet.String("analysis", "pointer", "type of call graph analysis to run. One of: pointer, cha, rta, static, vta")
	cgOut := flags.FlagSet.String("cgout", "", "output file for call graph (no output if not specified)")
	htmlOut := flags.FlagSet.String("htmlout", "", "output file for call graph (no output if not specified)")
	dfOut := flags.FlagSet.String("dfout", "", "output file for inter-procedural dataflow graph (no output if not specified)")
	ssaOut := flags.FlagSet.String("ssaout", "", "output folder for ssa (no output if not specified)")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command render with args %v: %v", args, err)
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
		},
		cgAnalysis: *cgAnalysis,
		cgOut:      *cgOut,
		htmlOut:    *htmlOut,
		dfOut:      *dfOut,
		ssaOut:     *ssaOut,
	}, nil
}

// Run runs the render tool with flags.
//
//gocyclo:ignore
func Run(flags Flags) error {
	// The strings constants are used only here
	var callgraphAnalysisMode lang.CallgraphAnalysisMode
	switch flags.cgAnalysis {
	case "pointer":
		callgraphAnalysisMode = lang.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = lang.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = lang.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = lang.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = lang.StaticAnalysis
	default:
		return fmt.Errorf("analysis %q not recognized", flags.cgAnalysis)
	}

	var err error
	renderConfig := config.NewDefault() // empty default config
	if flags.ConfigPath != "" {
		config.SetGlobalConfig(flags.ConfigPath)
		renderConfig, err = config.LoadGlobal()
		if err != nil {
			return fmt.Errorf("could not load config %q", flags.ConfigPath)
		}
	}

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	c := config.NewState(renderConfig, "", flags.FlagSet.Args(), loadOptions)
	c.Logger.Infof("Reading sources")
	wps, err := loadprogram.NewState(c).Value()
	if err != nil {
		return fmt.Errorf("could not load program: %v", err)
	}

	// Compute the call graph
	var cg *callgraph.Graph
	if flags.cgOut != "" || flags.htmlOut != "" {
		fmt.Fprintf(os.Stderr, formatutil.Faint("Computing call graph")+"\n")
		start := time.Now()
		cg, err = callgraphAnalysisMode.ComputeCallgraph(wps.Program)
		cgComputeDuration := time.Since(start).Seconds()
		if err != nil {
			return fmt.Errorf("could not compute callgraph: %v", err)
		}
		fmt.Fprintf(os.Stderr, formatutil.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))
	}

	if cg == nil {
		return fmt.Errorf("no callgraph, check the command arguments")
	}

	if flags.cgOut != "" {
		fmt.Fprintf(os.Stderr, formatutil.Faint("Writing call graph in "+flags.cgOut+"\n"))

		err = GraphvizToFile(renderConfig, cg, flags.cgOut)
		if err != nil {
			return fmt.Errorf("could not print callgraph: %v", err)
		}
	}

	if flags.htmlOut != "" {
		fmt.Fprintf(os.Stderr, formatutil.Faint("Writing call graph in "+flags.htmlOut+"\n"))
		err = WriteHTMLCallgrph(wps.Program, cg, flags.htmlOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not print callgraph: %v", err)
		}
	}

	if flags.dfOut != "" {
		fmt.Fprintf(os.Stderr, formatutil.Faint("Writing inter-procedural dataflow graph in "+flags.dfOut+"\n"))

		f, err := os.Create(flags.dfOut)
		if err != nil {
			return fmt.Errorf("could not create dataflow graph output file: %v", err)
		}
		defer f.Close()
		if err := WriteCrossFunctionGraph(wps, f); err != nil {
			return fmt.Errorf("could not generate inter-procedural flow graph: %v", err)
		}
	}

	if flags.ssaOut != "" {
		fmt.Fprintf(os.Stderr, formatutil.Faint("Generating SSA in ")+flags.ssaOut+"\n")
		err := OutputSsaPackages(wps.Program, flags.ssaOut)
		if err != nil {
			return fmt.Errorf("could not print ssa form: %v", err)
		}
	}

	return nil
}
