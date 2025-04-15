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
	"go/token"

	"golang.org/x/term"
)

const (
	cmdAstName              = "ast"
	cmdBacktraceName        = "backtrace"
	cmdBuildGraphName       = "buildgraph"
	cmdCalleesName          = "callees"
	cmdCallersName          = "callers"
	cmdCdName               = "cd"
	cmdExitName             = "exit"
	cmdFocusName            = "focus"
	cmdHelpName             = "help"
	cmdIntraName            = "intra"
	cmdLoadName             = "load" // TODO: deprecate this to make more sense given the other load functions
	cmdLoadPackagesName     = "load-pkg"
	cmdLoadWholeProgramName = "load-program"
	cmdListName             = "list"
	cmdLsName               = "ls"
	cmdMarkName             = "mark"
	cmdMayAliasName         = "mayalias"
	cmdPackageName          = "pkg"
	cmdRebuildName          = "rebuild"
	cmdReconfigName         = "reconfig"
	cmdScanName             = "scan"
	cmdShowPackageName      = "showpkg"
	cmdShowDataflowName     = "showdataflow"
	cmdShowEscapeName       = "showescape"
	cmdMembersName          = "members"
	cmdRunPointerName       = "run-pointer"
	cmdRunDataflowName      = "run-dataflow"
	cmdShowSsaName          = "showssa"
	cmdSrcName              = "src"
	cmdSsaInstrName         = "ssainstr"
	cmdSsaValueName         = "ssaval"
	cmdStateName            = "state?"
	cmdStatsName            = "stats"
	cmdSummarizeName        = "summarize"
	cmdSummaryName          = "summary"
	cmdTaintName            = "taint"
	cmdTraceName            = "trace"
	cmdUnfocusName          = "unfocus"
	cmdWhereName            = "where"
	// Other constants

	// Summarize threshold puts a maximum size above which summary building filters are used
	summarizeThreshold = 5
)

// ************ HELPERS *********

// NameAndLoc hold a name and location together
type NameAndLoc struct {
	name string
	loc  token.Position
}

func regexErr(tt *term.Terminal, expr string, err error) {
	WriteErr(tt, "Error while compiling %q into regex:", expr) // expr may come from config file
	WriteErr(tt, "  %s", err)                                  // err is safe
}
