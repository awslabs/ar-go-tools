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
	"strings"

	"golang.org/x/term"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the state.
func cmdLoad(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : load new program\n", tt.Escape.Blue, cmdLoadName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "%s expects at least one argument.", cmdLoadName)
		return false
	}
	sess.Args = command.Args
	return cmdRebuild(tt, sess, command, withTest)
}

func cmdLoadWholeProgram(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : laod the arguments as whole program\n", tt.Escape.Blue, cmdLoadName, tt.Escape.Reset)
		return false
	}

	lp := sess.loadProgram()
	if lp.IsErr() {
		WriteErr(tt, "%s", lp)
		return false
	} else {
		WriteSuccess(tt, "loaded program with path %s", strings.Join(sess.Args, ", "))
		return false
	}
}

func cmdRunPointer(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : run the pointer analysis\n", tt.Escape.Blue, cmdRunPointerName, tt.Escape.Reset)
		return false
	}

	ptr := sess.loadPtrAnalysis()
	if ptr.IsErr() {
		WriteErr(tt, "%s", ptr)
		return false
	} else {
		WriteSuccess(tt, "finished pointer analysis")
		return false
	}
}

func cmdRunDataflow(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : run the dataflow analysis\n", tt.Escape.Blue, cmdRunDataflowName, tt.Escape.Reset)
		return false
	}

	df := sess.loadDataflowAnalysis()
	if df.IsErr() {
		WriteErr(tt, "%s", df)
		return false
	} else {
		WriteSuccess(tt, "initialized dataflow analysis information")
		return false
	}
}

// cmdRebuild implements the rebuild command. It reloads the current config state and program state.
// The pointer and dataflow state are cleared.
func cmdRebuild(tt *term.Terminal, sess *session, _ Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including analyzer state.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	res := sess.loadConfig()
	if res.IsOk() {
		sess.loadProgram()
	} else {
		WriteErr(tt, "%s", res)
		return false
	}

	sess.CurrentFunction = nil
	sess.CurrentDataflowInformation = nil
	sess.InitialPackages = nil
	sess.LPState = nil
	sess.DFState = nil
	sess.PtrState = nil
	return false
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(tt *term.Terminal, sess *session, command Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : load the specified config file\n",
			tt.Escape.Blue, cmdReconfigName, tt.Escape.Reset)
		writeFmt(tt, "\t    Example: %s config.yaml\n", cmdReconfigName)
		return false
	}

	sess.ConfigPath = strings.TrimSpace(command.Args[0])
	oldConfig := sess.CfgState
	sess.CfgState = nil
	res := sess.loadConfig()

	if res.IsErr() {
		WriteErr(tt, "%s", res)
		WriteErr(tt, "You should reload the cli.")
		return false
	}
	if sess.CfgState == nil {
		WriteErr(tt, "Resetting to old config.")
		sess.CfgState = oldConfig
		return false
	}

	if len(command.Args) < 1 {
		WriteSuccess(tt, "Reloaded config from disk.")
	} else {
		WriteSuccess(tt, "Loaded new config!")
	}
	return false
}
