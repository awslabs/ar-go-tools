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

package main

import (
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// cmdCallers shows the callers of a given summarized function
func cmdCallers(tt *term.Terminal, c *dataflow.AnalyzerState, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callers of a given summarized function.\n",
			tt.Escape.Blue, cmdCallersName, tt.Escape.Reset)
		writeFmt(tt, "\t    %s will only be accurate after `%s%s%s`.\n",
			cmdCallersName, tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		writeFmt(tt, "\t    -ptr to use pointer analysis callgraph only.\n")
		return false
	}
	usePtr := false
	if command.Flags["ptr"] {
		usePtr = true
	}
	return displayCallInfo(tt, c, command, usePtr, false, true)
}

// cmdCallees shows the callers of a given summarized function
func cmdCallees(tt *term.Terminal, c *dataflow.AnalyzerState, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callees of a given summarized function.\n",
			tt.Escape.Blue, cmdCalleesName, tt.Escape.Reset)
		writeFmt(tt, "\t    %s will only be accurate after `%s%s%s`.\n",
			cmdCalleesName, tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		writeFmt(tt, "\t    -ptr to use pointer analysis callgraph only.\n")
		return false
	}
	usePtr := false
	if command.Flags["ptr"] {
		usePtr = true
	}
	return displayCallInfo(tt, c, command, usePtr, true, false)
}

// cmdIoFuncs shows the callers of all the I/O functions.
// Only uses the pointer analysis for now.
func cmdIoFuncs(tt *term.Terminal, s *dataflow.AnalyzerState, command Command) bool {
	if s == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callers of all the I/O functions.\n",
			tt.Escape.Blue, cmdCallersName, tt.Escape.Reset)
		return false
	}
	return displayIOFuncs(s, tt)
}

// displayCallInfo displays callers or/and callee information for a specific command.
// If displayCallees is true, displays the callees for each function matching the commands' argument
// If displayCaller is true, displays the callers for each function matching the commands' argument
//
// If the matching function has a summary, then the summary's info is used.
// Otherwise, the info contained in the pointer analysis' result is used.
func displayCallInfo(tt *term.Terminal, c *dataflow.AnalyzerState, command Command, usePtr bool,
	displayCallees bool, displayCallers bool) bool {
	targetFilter := func(f *ssa.Function) bool { return f != nil }

	if filterArg, hasArg := command.NamedArgs["filter"]; hasArg {
		filterRegex, err := regexp.Compile(filterArg)
		if err != nil {
			regexErr(tt, filterArg, err)
			return false
		}
		targetFilter = func(f *ssa.Function) bool {
			if f == nil {
				return false
			}
			return filterRegex.MatchString(f.String())
		}
	}

	for _, f := range funcsMatchingCommand(tt, c, command) {
		if summary, hasSummary := c.FlowGraph.Summaries[f]; hasSummary && !usePtr {
			// Strategy 1: the function has a summary, use it to determine callees
			// the information in a summary should be more complete than callgraph, if the callgraph sometimes
			// omits static calls
			displayCallInfoWithSummary(c, tt, f, summary, targetFilter, displayCallers, displayCallees)
		} else {
			// If there is no summary, or usePtr is true, then use the callgraph computed during
			// the pointer analysis  the state should always contain the pointer analysis,
			// and it should not be null
			displayCallInfoWithoutSummary(c, tt, f, targetFilter, displayCallers, displayCallees)
		}
	}
	return false
}

func displayCallInfoWithSummary(s *dataflow.AnalyzerState, tt *term.Terminal,
	f *ssa.Function, summary *dataflow.SummaryGraph,
	targetFilter func(*ssa.Function) bool,
	displayCallers bool, displayCallees bool) {

	if displayCallees {
		WriteSuccess(tt, "All functions called by %s:", f.String())
		for instr, callees := range summary.Callees {
			writeFmt(tt, "\tAt SSA instruction %s:\n", instr.String())
			writeFmt(tt, "\t Position %s:\n", s.Program.Fset.Position(instr.Pos()))
			for callee := range callees {
				if targetFilter(callee) {
					writeFmt(tt, "\t  %s\n", callee.String())
					writeFmt(tt, "\t    position: %s\n", s.Program.Fset.Position(callee.Pos()))
				}
			}
		}
	}
	if displayCallers {
		WriteSuccess(tt, "Callers of %s:", f.String())
		for _, callsite := range summary.Callsites {
			if targetFilter(callsite.Callee()) {
				writeFmt(tt, "\tAt SSA instruction %s\n", callsite.String())
				if callsite.Graph() != nil {
					writeFmt(tt, "\t  in %s\n", callsite.Graph().Parent.Name())
				}
				writeFmt(tt, "\t  position: %s\n", callsite.Position(s).String())
			}
		}
	}
}

func displayCallInfoWithoutSummary(s *dataflow.AnalyzerState, tt *term.Terminal,
	f *ssa.Function, targetFilter func(*ssa.Function) bool,
	displayCallers bool, displayCallees bool) {
	if node, ok := s.PointerAnalysis.CallGraph.Nodes[f]; ok {
		if displayCallees {
			WriteSuccess(tt, "All functions called by %s:", f.String())
			for _, out := range node.Out {
				if out.Callee != nil && targetFilter(out.Callee.Func) {
					if out.Site != nil {
						writeFmt(tt, "\tAt SSA instruction %s:\n", out.Site.String())
						writeFmt(tt, "\t - position: %s\n", s.Program.Fset.Position(out.Site.Pos()))
					}
					writeFmt(tt, "\t - %s\n", out.Callee.Func.String())
				}
			}
		}
		if displayCallers {
			WriteSuccess(tt, "Callers of %s:", f.String())
			for _, in := range node.In {
				if in.Caller != nil && targetFilter(in.Caller.Func) {
					if in.Site != nil {
						writeFmt(tt, "\tAt SSA instruction %s:\n", in.Site.String())
						writeFmt(tt, "\t - position: %s\n", s.Program.Fset.Position(in.Site.Pos()))
					}
					writeFmt(tt, "\t - %s\n", in.Caller.Func.String())
				}
			}
		}
	}
}

func displayIOFuncs(s *dataflow.AnalyzerState, tt *term.Terminal) bool {
	io := ioFuncs(s)
	targetFilter := func(call ssa.CallInstruction) bool {
		pos := s.Program.Fset.Position(call.Pos())
		if !pos.IsValid() {
			return false
		}

		// filter out unwanted callsites
		fname := pos.Filename
		// NOTE hardcoded for the agent for now
		return strings.Contains(fname, "amazon-ssm-agent/agent") && !strings.Contains(fname, "test")
	}

	n := 0
	for _, f := range io {
		if node, ok := s.PointerAnalysis.CallGraph.Nodes[f]; ok {
			WriteSuccess(tt, "Callers of %s:", f.String())
			for _, in := range node.In {
				if in.Caller != nil && targetFilter(in.Site) {
					if in.Site != nil {
						writeFmt(tt, "\tAt SSA instruction %s:\n", in.Site.String())
						writeFmt(tt, "\t - position: %s\n", s.Program.Fset.Position(in.Site.Pos()))
					}
					writeFmt(tt, "\t - %s\n", in.Caller.Func.String())
					n++
				}
			}
		}
	}
	writeFmt(tt, "%d total I/O funcs in program\n", n)

	return false
}

func ioFuncs(s *dataflow.AnalyzerState) []*ssa.Function {
	fns := ssautil.AllFunctions(s.Program)
	res := []*ssa.Function{}
	for f := range fns {
		if _, ok := ioFuncNames[f.String()]; !ok {
			for name := range ioFuncNames {
				if strings.Contains(f.String(), name) {
					break
				}
			}

			continue
		}

		res = append(res, f)
	}

	return res
}

var ioFuncNames = map[string]struct{}{
	"log.SetFlags":                      {},
	"log.SetOutput":                     {},
	"net.Dial":                          {},
	"net.DialIP":                        {},
	"net.DialTCP":                       {},
	"net.DialTimeout":                   {},
	"net.DialUDP":                       {},
	"net.DialUnix":                      {},
	"net.FileConn":                      {},
	"net.FileListener":                  {},
	"net.FilePacketConn":                {},
	"net.Listen":                        {},
	"net.ListenIP":                      {},
	"net.ListenMulticastUDP":            {},
	"net.ListenPacket":                  {},
	"net.ListenTCP":                     {},
	"net.ListenUDP":                     {},
	"net.ListenUnix":                    {},
	"net.ListenUnixgram":                {},
	"net.LookupAddr":                    {},
	"net.LookupCNAME":                   {},
	"net.LookupHost":                    {},
	"net.LookupIP":                      {},
	"net.LookupMX":                      {},
	"net.LookupNS":                      {},
	"net.LookupPort":                    {},
	"net.LookupSRV":                     {},
	"net.LookupTXT":                     {},
	"net.ResolveIPAddr":                 {},
	"net.ResolveTCPAddr":                {},
	"net.ResolveUDPAddr":                {},
	"net.ResolveUnixAddr":               {},
	"os.Chdir":                          {},
	"os.Chmod":                          {},
	"os.Chown":                          {},
	"os.Chtimes":                        {},
	"os.Clearenv":                       {},
	"os.Create":                         {},
	"os.CreateTemp":                     {},
	"os.DirFS":                          {},
	"os.Lchown":                         {},
	"os.Link":                           {},
	"os.Lstat":                          {},
	"os.Mkdir":                          {},
	"os.MkdirAll":                       {},
	"os.MkdirTemp":                      {},
	"os.NewFile":                        {},
	"os.Open":                           {},
	"os.OpenFile":                       {},
	"os.Pipe":                           {},
	"os.ReadDir":                        {},
	"os.ReadFile":                       {},
	"os.Readlink":                       {},
	"os.Remove":                         {},
	"os.RemoveAll":                      {},
	"os.Rename":                         {},
	"os.SameFile":                       {},
	"os.Setenv":                         {},
	"os.Stat":                           {},
	"os.Symlink":                        {},
	"os.Truncate":                       {},
	"os.Unsetenv":                       {},
	"os.WriteFile":                      {},
	"(*os.File).Chdir":                  {},
	"(*os.File).Chmod":                  {},
	"(*os.File).Chown":                  {},
	"(*os.File).Close":                  {},
	"(*os.File).Fd":                     {},
	"(*os.File).Name":                   {},
	"(*os.File).Read":                   {},
	"(*os.File).ReadAt":                 {},
	"(*os.File).ReadDir":                {},
	"(*os.File).ReadFrom":               {},
	"(*os.File).Readdir":                {},
	"(*os.File).Readdirnames":           {},
	"(*os.File).Seek":                   {},
	"(*os.File).SetDeadline":            {},
	"(*os.File).SetReadDeadline":        {},
	"(*os.File).SetWriteDeadline":       {},
	"(*os.File).Stat":                   {},
	"(*os.File).Sync":                   {},
	"(*os.File).SyscallConn":            {},
	"(*os.File).Truncate":               {},
	"(*os.File).Write":                  {},
	"(*os.File).WriteAt":                {},
	"(*os.File).WriteString":            {},
	"(*os.fileStat).IsDir":              {},
	"(*os.fileStat).ModTime":            {},
	"(*os.fileStat).Mode":               {},
	"(*os.fileStat).Name":               {},
	"(*os.fileStat).Size":               {},
	"(*os.fileStat).Sys":                {},
	"(*os.unixDirent).Name":             {},
	"os/exec.LookPath":                  {},
	"plugin.Open":                       {},
	"runtime.Breakpoint":                {},
	"runtime.CPUProfile":                {},
	"runtime.Goexit":                    {},
	"runtime.SetCgoTraceback":           {},
	"runtime.UnlockOSThread":            {},
	"runtime/debug.SetGCPercent":        {},
	"runtime/debug.SetMaxStack":         {},
	"runtime/debug.SetMaxThreads":       {},
	"runtime/debug.SetPanicOnFault":     {},
	"runtime/debug.WriteHeapDump":       {},
	"runtime/metrics.Read":              {},
	"runtime.SetFinalizer":              {},
	"internal/syscall/unix":             {},
	"internal/syscall/windows":          {},
	"internal/syscall/windows/registry": {},
	"os":                                {},
	"os/exec":                           {},
	"os/signal":                         {},
	"reflect":                           {},
	"runtime":                           {},
	"runtime/cgo":                       {},
	"runtime/debug":                     {},
	"runtime/internal/syscall":          {},
	"runtime/pprof":                     {},
	"syscall":                           {},
	"net":                               {},
	"net/http":                          {},
	"unsafe":                            {},
	"golang.org/x/sys/unix":             {},
	"fmt.Print":                         {},
	"fmt.Printf":                        {},
	"fmt.Println":                       {},
}
