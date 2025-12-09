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

package cli

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/refactor/statefulrewrite"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Session stores state information about the current cli Session
type Session struct {
	// args is always the args provided to load a program. Set either when starting the cli, or the load command.
	args []string
	// target is the optional target provided when starting the cli, or the load -target command.
	target          string
	configPath      string
	withTest        bool
	verbose         bool
	initialPackages []*packages.Package

	termWidth int

	currentFunction *ssa.Function

	currentDataflowInformation *dataflow.FlowInformation

	isTt bool

	// Available states

	// pkgs contains the packages last loaded by a cmdLoadPackages command or by loading the program
	pkgs     map[string]*packages.Package
	cfgState *config.State
	lpState  *loadprogram.State
	ptrState *ptr.State
	dfState  *dataflow.State
}

// NewSession returns a new session with the provided flags.
func NewSession(flags tools.CommonFlags, isTt bool) *Session {
	s := &Session{
		withTest:   flags.WithTest,
		configPath: flags.ConfigPath,
		target:     flags.Targets,
		verbose:    flags.Verbose,
		isTt:       isTt,
	}
	if flags.FlagSet != nil {
		s.args = flags.FlagSet.Args()
	}
	return s
}

// Reset the session (clear all the program state fields)
func (s *Session) Reset() {
	s.pkgs = nil
	s.currentFunction = nil
	s.initialPackages = nil
	s.cfgState = nil
	s.lpState = nil
	s.dfState = nil
	s.ptrState = nil
	s.currentDataflowInformation = nil
}

func (s *Session) logger() *config.LogGroup {
	if s.cfgState != nil {
		return s.cfgState.Logger
	}
	return config.NewLogGroup(nil)
}

func (s *Session) allFunctions() (map[*ssa.Function]bool, error) {
	if s.lpState == nil {
		return nil, fmt.Errorf("listing functions requires at least a loaded program or package")
	}
	return ssautil.AllFunctions(s.lpState.Program), nil
}

func (s *Session) reachableFunctions(o Outputter) (map[*ssa.Function]bool, error) {
	if s.lpState == nil {
		_, err := s.loadProgram(o).Value()
		if err != nil {
			return nil, fmt.Errorf("failed to load program to get reachable functions: %w", err)
		}
	}
	if s.dfState != nil {
		return s.dfState.ReachableFunctions(), nil
	}
	if s.ptrState != nil {
		return s.ptrState.ReachableFunctions(), nil
	}
	if s.lpState == nil {
		panic("nilaway: program should have been loaded or error thrown here")
	}
	return s.lpState.ReachableFunctions()
}

func (s *Session) hasSummary(f *ssa.Function) (*dataflow.SummaryGraph, bool) {
	if s.dfState == nil || s.dfState.FlowGraph == nil {
		return nil, false
	}
	summary, ok := s.dfState.FlowGraph.Summaries[f]
	if summary == nil {
		return nil, false
	}
	return summary, ok
}

func (s *Session) seekConfig() (*config.Config, bool, error) {
	var err error
	pConfig := config.NewDefault()
	if s.configPath != "" {
		config.SetGlobalConfig(s.configPath)
		pConfig, err = config.LoadGlobal(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %q\n", s.configPath)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return nil, true, nil
		}
	} else if len(s.args) == 1 && strings.HasSuffix(s.args[0], ".go") {
		// Special case: look for config in .go 's folder, if found then set it
		dir := path.Dir(s.args[0])
		if s.attemptSettingConfig(&pConfig, dir, "config.yaml") == nil {
			return pConfig, false, nil
		}
		err = s.attemptSettingConfig(&pConfig, dir, "config.json")
	}
	return pConfig, false, err
}

func (s *Session) attemptSettingConfig(pConfig **config.Config, dir string, filename string) error {
	configFile := filepath.Join(dir, filename)
	config.SetGlobalConfig(configFile)
	tmpConfig, err := config.LoadGlobal(nil)
	if err != nil {
		// Reset and ignore
		config.SetGlobalConfig("")
		return err
	}
	*pConfig = tmpConfig
	return nil
}

// LoadConfig triggers the config loading for the session.
// Does nothing when the config state is non-null and reload is not true.
func (s *Session) LoadConfig(o Outputter, reload bool) result.Result[config.State] {
	if s.cfgState != nil && !reload {
		return result.Ok(s.cfgState)
	}

	// This also works without a config.
	pConfig, done, _ := s.seekConfig()
	if done {
		return result.Err[config.State](fmt.Errorf("failed to load config"))
	}

	if pConfig == nil {
		fmt.Fprintf(os.Stderr, "failed to load config")
		return result.Err[config.State](fmt.Errorf("failed to load config"))
	}
	// Override config parameters with command-line parameters
	if s.verbose {
		pConfig.LogLevel = int(config.DebugLevel)
	}
	o.Write(formatutil.Faint("Reading sources") + "\n")
	// Load the program
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     s.withTest,
		ApplyRewrites: true,
	}
	// New state is initialized with the session args => the patterns in the config
	s.cfgState = config.NewState(pConfig, "", s.args, loadOptions)
	s.cfgState.Logger.SetAllOutput(o.Writer())
	// Apply rewrites from config if the target can be recognized
	for _, targetSpec := range s.cfgState.Config.Targets {
		if slices.Equal(targetSpec.Files, s.args) {
			if targetSpec.UseProgramTransforms && len(targetSpec.ReflectValueCallInstances) >= 1 {
				var err error
				s.logger().Infof(
					"Reflect value call instances specified. " +
						"Tool supports only 1 for now, will use the first.")
				// TODO: handle more rewrites later
				s.cfgState, err = statefulrewrite.StatefulRewritesOverlayTransform(s.cfgState,
					statefulrewrite.StatefulRewritesOverlayTransformSpec{
						ReflectValueCallInstanceCid: targetSpec.ReflectValueCallInstances[0]}).Value()
				if err != nil {
					panic(err)
				}
			}
		}
	}
	// If the -targets option has been provided the cli should load the target, unless args have been provided
	// The -targets option for the cli should only contain one target
	if s.target != "" && len(s.args) == 0 {
		targetInfo, ok := s.cfgState.Config.GetTargetMap()[s.target]
		if !ok {
			return result.Err[config.State](fmt.Errorf("target %s is not in config", s.target))
		}
		s.cfgState.Patterns = targetInfo.Patterns
	}
	return result.Ok(s.cfgState)
}

// loadProgram loads the program specified by the config state if the program is not already loaded.
// If the caller wants to laod a new program, it should set the lpstate to nil and set the parameters
// of the config state (specifically, the Patterns of the config).
func (s *Session) loadProgram(o Outputter) result.Result[loadprogram.State] {
	if s.lpState != nil {
		// Program is already loaded!
		return result.Ok(s.lpState)
	}
	// Ensures s.cfgState is present
	s.LoadConfig(o, false)
	lpstate := loadprogram.NewState(s.cfgState)
	if lpstate.IsOk() {
		s.lpState = lpstate.Unwrap()
		// Populate the packages
		if s.pkgs == nil {
			s.pkgs = make(map[string]*packages.Package)
		}
		for _, pkg := range s.lpState.Packages {
			s.pkgs[pkg.PkgPath] = pkg
		}
	}
	o.WriteSuccess("loaded program with path %s", strings.Join(s.args, ", "))
	o.WriteSuccess("✔ loaded %d packages", len(s.pkgs))
	// Attempt to print the main package given current information.
	// It may fail; it's ok because we don't have the best call graph information yet.
	if main, err := s.lpState.FindMain(); err == nil {
		o.WriteSuccess("✔ main package: %s. Use this package when looking for the main entry point.", main.Pkg.String())
	} else {
		o.Write("No main package loaded. Pointer and other analyses will not work.\n")
	}
	return lpstate
}

func (s *Session) loadPtrAnalysis(o Outputter) result.Result[ptr.State] {
	if s.ptrState != nil {
		return result.Ok(s.ptrState)
	}
	ptrstate := result.Bind(s.loadProgram(o), ptr.NewState)
	if ptrstate.IsOk() {
		s.ptrState = ptrstate.Unwrap()
	}
	return ptrstate
}

func (s *Session) loadDataflowAnalysis(o Outputter) result.Result[dataflow.State] {
	if s.dfState != nil {
		return result.Ok(s.dfState)
	}
	dfstate := result.Bind(s.loadPtrAnalysis(o), dataflow.NewState)
	if dfstate.IsOk() {
		s.dfState = dfstate.Unwrap()
	} else {
		return dfstate
	}
	// Optional step: running the preamble of the taint analysis
	if s.dfState.Config.UseEscapeAnalysis || len(s.dfState.Config.TaintTrackingProblems) > 0 {
		err := taint.AnalysisPreamble(s.dfState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while running the taint analysis preamble: %v", err)
			os.Exit(1)
		}
	}
	return result.Ok(s.dfState)
}

func (s *Session) hasProgram() bool {
	return s.lpState != nil && s.lpState.Program != nil
}

func (s *Session) program() (*ssa.Program, error) {
	if s.lpState == nil || s.lpState.Program == nil {
		return nil, fmt.Errorf("no program loaded")
	}
	return s.lpState.Program, nil
}

// programOrPanic is a version of program that panics instead of returning an error.
// This is useful in a context where you know the program exists.
func (s *Session) programOrPanic() *ssa.Program {
	program, err := s.program()
	if err != nil {
		panic(err)
	}
	return program
}

// funcsMatchingCommand returns the function matching the argument of the command or all functions if there
// is no argument
// Returns an empty list if any error is encountered
func (s *Session) funcsMatchingCommand(o Outputter, command Command) ([]*ssa.Function, error) {
	rString := ".*" // default is to match anything
	if len(command.Args) >= 1 {
		// otherwise build regex from arguments
		var x []string
		for _, arg := range command.Args {
			x = append(x, "("+arg+")")
		}
		rString = strings.Join(x, "|")
	}
	r, err := regexp.Compile(rString)
	if err != nil {
		regexErr(o, rString, err)
		return []*ssa.Function{}, err
	}
	funcs, err := s.findFunc(r)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(funcs, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
	return funcs, nil
}

func (s *Session) findFunc(target *regexp.Regexp) ([]*ssa.Function, error) {
	var funcs []*ssa.Function
	allFuncs, err := s.allFunctions()
	if err != nil {
		return nil, err
	}
	for f := range allFuncs {
		if target.MatchString(f.String()) {
			funcs = append(funcs, f)
		}
	}
	return funcs, nil
}

// Help command
func cmdHelp(o Outputter, s *Session, _ Command, withTest bool) bool {
	if s == nil {
		o.Write("\t- %s%s%s : print help message\t", CmdHelpName, o.EscBlue(), o.EscReset())
		return false
	}
	o.Write("Commands:\n")
	o.Write("\t- %s%s%s : print this message\n", o.EscBlue(), CmdHelpName, o.EscReset())
	keys := maps.Keys(Commands)
	slices.Sort(keys)
	for _, key := range keys {
		cmd := Commands[key]
		cmd.Function(o, nil, Command{}, withTest)
	}
	return false
}

// cmdState implements the "state?" command, which prints information about the current state of the tool
func cmdState(o Outputter, s *Session, _ Command, _ bool) bool {
	if s == nil {
		o.Write("\t- %s%s%s : print information about the current Session\n",
			o.EscBlue(), CmdStateName, o.EscReset())
		return false
	}
	wd, _ := os.Getwd()
	fName := "none"
	if s.currentFunction != nil {
		fName = s.currentFunction.String()
	}
	programPath := strings.Join(s.args, " ")
	if s.cfgState != nil {
		programPath = strings.Join(s.cfgState.Patterns, " ")
	}
	o.Write("Program path          : %s\n", programPath)
	o.Write("Config path           : %s\n", s.configPath)
	o.Write("Working dir           : %s\n", wd)
	o.Write("Focused function      : %s\n", fName)
	if s.cfgState != nil && s.cfgState.Config != nil && s.configPath != "" {
		o.Write("┌────────── CONFIG ──────\n")
		o.Write("│ # targets        : %d\n", len(s.cfgState.Config.Targets))
		for _, target := range s.cfgState.Config.Targets {
			o.Write("│ - %s\n", target.Name)
		}
		o.Write("│ # current target : %s\n", s.cfgState.Target)
		o.Write("└─────────────────────\n")
	} else {
		o.Write("┌───────────────────────────┐\n")
		o.Write("│ ⚠ Config not loaded       │\n")
		o.Write("└───────────────────────────┘\n")
	}
	if s.lpState != nil {
		o.Write("┌────────── SSA ──────\n")
		o.Write("│ # packages        : %d\n", len(s.lpState.Packages))
		r, err := s.lpState.ReachableFunctions()
		if err != nil {
			o.Write("error: %s\n", err)
			return false
		}
		o.Write("│ # reachable functions : %d\n", len(r))
		o.Write("└─────────────────────\n")
	} else {
		o.Write("┌───────────────────────────┐\n")
		o.Write("│ ⚠ SSA Program not loaded  │\n")
		o.Write("└───────────────────────────┘\n")
		return false
	}
	if s.ptrState != nil {
		o.Write("┌────────── POINTERS ────\n")
		o.Write("│ # pointers        : %d\n", len(s.ptrState.PointerAnalysis.Queries))
		o.Write("└────────────────────────\n")
	} else {
		o.Write("┌──────────────────────────────┐\n")
		o.Write("│ ⚠ Pointer Analysis not run   │\n")
		o.Write("└──────────────────────────────┘\n")
		return false
	}
	if s.dfState != nil {
		o.Write("┌────────── DATAFLOW ───\n")
		o.Write("│ # functions           : %d\n", len(s.dfState.ReachableFunctions()))
		o.Write("│ # summaries built     : %d\n", len(s.dfState.FlowGraph.Summaries))
		o.Write("│ flow graph built?     : %t\n", s.dfState.FlowGraph.IsBuilt())
		o.Write("└──────────────────────\n")
	} else {
		o.Write("┌──────────────────────────────┐\n")
		o.Write("│ ⚠ Dataflow Analysis not run  │\n")
		o.Write("└──────────────────────────────┘\n")
	}
	return false
}

// cmdList shows all functions matching a given regex
func cmdList(o Outputter, s *Session, command Command, withTest bool) bool {
	if s == nil {
		o.Write("\t- %s%s%s : list all functions matching provided regexes\n",
			o.EscBlue(), CmdListName, o.EscReset())
		o.Write("\t  Options:\n")
		o.Write("\t    -r     list only reachable functions\n")
		o.Write("\t    -s     list only summarized functions\n")
		o.Write("\t    -h     print this help message\n")
		return false
	}

	if command.Flags["h"] {
		return cmdList(o, nil, command, withTest)
	}

	funcs, err := s.funcsMatchingCommand(o, command)

	if err != nil {
		o.WriteErr("Error: %s", err)
		return false
	}
	if len(funcs) == 0 {
		o.WriteSuccess("No matching function found.")
		return false
	}

	reachable, err := s.reachableFunctions(o)
	if err != nil {
		o.WriteErr("Error: %s", err)
		return false
	}

	o.WriteSuccess("Found %d matching functions:", len(funcs))
	o.WriteSuccess("[summarized?][reachable?] function name")

	numSummarized := 0
	numReachable := 0
	for _, fun := range funcs {
		summary, hasSummary := s.hasSummary(fun)
		isReachable := reachable[fun]
		reachStr := "_"
		if isReachable {
			reachStr = "x"
			numReachable++
		} else if command.Flags["r"] {
			// -r means print only reachable functions
			continue
		}
		if hasSummary && summary.Constructed {
			o.Write("%s[x][%s] %s%s\n", o.EscCyan(), reachStr, fun.String(), o.EscReset())
			numSummarized++
		} else if isReachable && !command.Flags["s"] {
			o.Write("%s[_][%s] %s%s\n", o.EscMagenta(), reachStr, fun.String(), o.EscReset())
		} else if !command.Flags["s"] && !command.Flags["r"] {
			o.Write("[_][%s] %s\n", reachStr, fun.String())
		}
	}
	o.WriteSuccess("(%d matching functions, %d reachable, %d summarized)", len(funcs),
		numReachable, numSummarized)
	return false
}
