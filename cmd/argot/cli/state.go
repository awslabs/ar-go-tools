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
	"log"
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
	"golang.org/x/term"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// session stores state information about the current cli session
type session struct {
	originalFlags tools.CommonFlags

	args       []string
	configPath string

	initialPackages []*packages.Package

	termWidth int

	currentFunction *ssa.Function

	currentDataflowInformation *dataflow.FlowInformation

	// Available states

	// pkgs contains the packages last loaded by a cmdLoadPackages command
	pkgs     map[string]*packages.Package
	cfgState *config.State
	lpState  *loadprogram.State
	ptrState *ptr.State
	dfState  *dataflow.State
}

func newSession(flags tools.CommonFlags) *session {
	s := &session{
		originalFlags: flags,
		args:          flags.FlagSet.Args(),
		configPath:    flags.ConfigPath,
	}
	return s
}

func (s *session) logger() *config.LogGroup {
	if s.cfgState != nil {
		return s.cfgState.Logger
	}
	return config.NewLogGroup(nil)
}

func (s *session) allFunctions() (map[*ssa.Function]bool, error) {
	if s.lpState == nil {
		return nil, fmt.Errorf("listing functions requires at least a loaded program or package")
	}
	return ssautil.AllFunctions(s.lpState.Program), nil
}

func (s *session) reachableFunctions() (map[*ssa.Function]bool, error) {
	if s.lpState == nil {
		_, err := s.loadProgram().Value()
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

func (s *session) hasSummary(f *ssa.Function) (*dataflow.SummaryGraph, bool) {
	if s.dfState == nil || s.dfState.FlowGraph == nil {
		return nil, false
	}
	summary, ok := s.dfState.FlowGraph.Summaries[f]
	if summary == nil {
		return nil, false
	}
	return summary, ok
}

func (s *session) seekConfig() (*config.Config, bool, error) {
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

func (s *session) attemptSettingConfig(pConfig **config.Config, dir string, filename string) error {
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

func (s *session) loadConfig() result.Result[config.State] {
	logger := log.New(os.Stdout, "", log.Flags())
	if s.cfgState != nil {
		return result.Ok(s.cfgState)
	}

	pConfig, done, _ := s.seekConfig()
	if done {
		return result.Err[config.State](fmt.Errorf("failed to load config"))
	}

	if pConfig == nil {
		fmt.Fprintf(os.Stderr, "failed to load config")
		return result.Err[config.State](fmt.Errorf("failed to load config"))
	}
	// Override config parameters with command-line parameters
	if s.originalFlags.Verbose {
		pConfig.LogLevel = int(config.DebugLevel)
	}
	logger.Printf(formatutil.Faint("Reading sources") + "\n")
	// Load the program
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     s.originalFlags.WithTest,
		ApplyRewrites: true,
	}
	s.cfgState = config.NewState(pConfig, "", s.originalFlags.FlagSet.Args(), loadOptions)
	// Apply rewrites from config if the target can be recognized
	for _, targetSpec := range s.cfgState.Config.Targets {
		if slices.Equal(targetSpec.Files, s.args) {
			if targetSpec.UseProgramTransforms && len(targetSpec.ReflectValueCallInstances) >= 1 {
				var err error
				s.logger().Infof("Reflect value call instances specified. Tool supports only 1 for now, will use the first.")
				// TODO: handle more rewrites later
				s.cfgState, err = statefulrewrite.StatefulRewritesOverlayTransform(s.cfgState,
					statefulrewrite.StatefulRewritesOverlayTransformSpec{ReflectValueCallInstanceCid: targetSpec.ReflectValueCallInstances[0]}).Value()
				if err != nil {
					panic(err)
				}
			}
		}
	}
		// If the -targets option has been provided the cli should load the target
	// The -targets option for the cli should only contain one target
	if s.originalFlags.Targets != "" {
		if len(strings.Split(s.originalFlags.Targets, ",")) > 1 {
			return result.Err[config.State](fmt.Errorf("-targets should only have one target in cli"))
		}
		targetInfo, ok := s.cfgState.Config.GetTargetMap()[s.originalFlags.Targets]
		if !ok {
			return result.Err[config.State](fmt.Errorf("target %s is not in config", s.originalFlags.Targets))
		}
		s.cfgState.Patterns = targetInfo.Patterns
	}
	return result.Ok(s.cfgState)
}

func (s *session) loadProgram() result.Result[loadprogram.State] {
	if s.lpState != nil {
		return result.Ok(s.lpState)
	}
	lpstate := loadprogram.NewState(s.cfgState)
	if lpstate.IsOk() {
		s.lpState = lpstate.Unwrap()
	}
	return lpstate
}

func (s *session) loadPtrAnalysis() result.Result[ptr.State] {
	if s.ptrState != nil {
		return result.Ok(s.ptrState)
	}
	ptrstate := result.Bind(s.loadProgram(), ptr.NewState)
	if ptrstate.IsOk() {
		s.ptrState = ptrstate.Unwrap()
	}
	return ptrstate
}

func (s *session) loadDataflowAnalysis() result.Result[dataflow.State] {
	if s.dfState != nil {
		return result.Ok(s.dfState)
	}
	dfstate := result.Bind(s.loadPtrAnalysis(), dataflow.NewState)
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

func (s *session) hasProgram() bool {
	return s.lpState != nil && s.lpState.Program != nil
}

func (s *session) program() (*ssa.Program, error) {
	if s.lpState == nil || s.lpState.Program == nil {
		return nil, fmt.Errorf("no program loaded")
	}
	return s.lpState.Program, nil
}

// programOrPanic is a version of program that panics instead of returning an error.
// This is useful in a context where you know the program exists.
func (s *session) programOrPanic() *ssa.Program {
	program, err := s.program()
	if err != nil {
		panic(err)
	}
	return program
}

// funcsMatchingCommand returns the function matching the argument of the command or all functions if there
// is no argument
// Returns an empty list if any error is encountered
func (s *session) funcsMatchingCommand(tt *term.Terminal, command Command) ([]*ssa.Function, error) {
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
		regexErr(tt, rString, err)
		return []*ssa.Function{}, err
	}
	funcs, err := s.findFunc(r)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(funcs, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
	return funcs, nil
}

func (s *session) findFunc(target *regexp.Regexp) ([]*ssa.Function, error) {
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
func cmdHelp(tt *term.Terminal, s *session, _ Command, withTest bool) bool {
	if s == nil {
		writeFmt(tt, "\t- %s%s%s : print help message\t", cmdHelpName, tt.Escape.Blue, tt.Escape.Reset)
		return false
	}
	writeFmt(tt, "Commands:\n")
	writeFmt(tt, "\t- %s%s%s : print this message\n", tt.Escape.Blue, cmdHelpName, tt.Escape.Reset)
	keys := maps.Keys(commands)
	slices.Sort(keys)
	for _, key := range keys {
		cmd := commands[key]
		cmd(tt, nil, Command{}, withTest)
	}
	return false
}

// cmdState implements the "state?" command, which prints information about the current state of the tool
func cmdState(tt *term.Terminal, s *session, _ Command, _ bool) bool {
	if s == nil {
		writeFmt(tt, "\t- %s%s%s : print information about the current session\n",
			tt.Escape.Blue, cmdStateName, tt.Escape.Reset)
		return false
	}
	wd, _ := os.Getwd()
	fName := "none"
	if s.currentFunction != nil {
		fName = s.currentFunction.String()
	}
	writeFmt(tt, "Program path          : %s\n", strings.Join(s.args, " "))
	writeFmt(tt, "Config path           : %s\n", s.configPath)
	writeFmt(tt, "Working dir           : %s\n", wd)
	writeFmt(tt, "Focused function      : %s\n", fName)
	if s.lpState != nil {
		writeFmt(tt, "┌────────── SSA ──────")
		writeFmt(tt, "│ # packages        : %d\n", len(s.lpState.Packages))
		r, err := s.lpState.ReachableFunctions()
		if err != nil {
			writeFmt(tt, "error: %s\n", err)
			return false
		}
		writeFmt(tt, "│ # reachable functions : %d\n", len(r))
		writeFmt(tt, "└─────────────────────")
	} else {
		writeFmt(tt, "┌───────────────────────────┐")
		writeFmt(tt, "│ ⚠ SSA Program not loaded  │")
		writeFmt(tt, "└───────────────────────────┘")
		return false
	}
	if s.ptrState != nil {
		writeFmt(tt, "┌────────── POINTERS ────")
		writeFmt(tt, "│ # pointers        : %d\n", len(s.ptrState.PointerAnalysis.Queries))
		writeFmt(tt, "└────────────────────────")
	} else {
		writeFmt(tt, "┌──────────────────────────────┐")
		writeFmt(tt, "│ ⚠ Pointer Analysis not run   │")
		writeFmt(tt, "└──────────────────────────────┘")
		return false
	}
	if s.dfState != nil {
		writeFmt(tt, "┌────────── DATAFLOW ───")
		writeFmt(tt, "│ # functions           : %d\n", len(s.dfState.ReachableFunctions()))
		writeFmt(tt, "│ # summaries built     : %d\n", len(s.dfState.FlowGraph.Summaries))
		writeFmt(tt, "│ flow graph built?     : %t\n", s.dfState.FlowGraph.IsBuilt())
		writeFmt(tt, "└──────────────────────")
	} else {
		writeFmt(tt, "┌──────────────────────────────┐")
		writeFmt(tt, "│ ⚠ Dataflow Analysis not run  │")
		writeFmt(tt, "└──────────────────────────────┘")
	}
	return false
}

// cmdList shows all functions matching a given regex
func cmdList(tt *term.Terminal, s *session, command Command, withTest bool) bool {
	if s == nil {
		writeFmt(tt, "\t- %s%s%s : list all functions matching provided regexes\n",
			tt.Escape.Blue, cmdListName, tt.Escape.Reset)
		writeFmt(tt, "\t  Options:\n")
		writeFmt(tt, "\t    -r     list only reachable functions\n")
		writeFmt(tt, "\t    -s     list only summarized functions\n")
		writeFmt(tt, "\t    -h     print this help message\n")
		return false
	}

	if command.Flags["h"] {
		return cmdList(tt, nil, command, withTest)
	}

	funcs, err := s.funcsMatchingCommand(tt, command)

	if err != nil {
		WriteErr(tt, "Error: %s", err)
		return false
	}
	if len(funcs) == 0 {
		WriteSuccess(tt, "No matching function found.")
		return false
	}

	reachable, err := s.reachableFunctions()
	if err != nil {
		WriteErr(tt, "Error: %s", err)
		return false
	}

	WriteSuccess(tt, "Found %d matching functions:", len(funcs))
	WriteSuccess(tt, "[summarized?][reachable?] function name")

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
			writeFmt(tt, "%s[x][%s] %s%s\n", tt.Escape.Cyan, reachStr, fun.String(), tt.Escape.Reset)
			numSummarized++
		} else if isReachable && !command.Flags["s"] {
			writeFmt(tt, "%s[_][%s] %s%s\n", tt.Escape.Magenta, reachStr, fun.String(), tt.Escape.Reset)
		} else if !command.Flags["s"] && !command.Flags["r"] {
			writeFmt(tt, "[_][%s] %s\n", reachStr, fun.String())
		}
	}
	WriteSuccess(tt, "(%d matching functions, %d reachable, %d summarized)", len(funcs),
		numReachable, numSummarized)
	return false
}
