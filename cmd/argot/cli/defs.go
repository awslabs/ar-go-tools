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
)

const (
	// CmdAstName is the name of the ast command
	CmdAstName = "ast"
	// CmdBacktraceName is the name of the backtrace command
	CmdBacktraceName = "backtrace"
	// CmdBuildGraphName is the name of the buildgraph command
	CmdBuildGraphName = "buildgraph"
	// CmdCalleesName is the name of the callees command
	CmdCalleesName = "callees"
	// CmdCallersName is the name of the callers command
	CmdCallersName = "callers"
	// CmdCdName is the name of the cd command
	CmdCdName = "cd"
	// CmdCheckName is the name of the check command
	CmdCheckName = "check"
	// CmdExitName is the name of the exit command
	CmdExitName = "exit"
	// CmdFocusName is the name of the focus command
	CmdFocusName = "focus"
	// CmdHelpName is the name of the help command
	CmdHelpName = "help"
	// CmdIntraName is the name of the intra command
	CmdIntraName = "intra"
	// CmdLoadName is the name of the load command
	CmdLoadName = "load"
	// CmdLoadPackagesName is the name of the load-pkg command
	CmdLoadPackagesName = "load-pkg"
	// CmdLoadWholeProgramName is the name of the load-program command
	CmdLoadWholeProgramName = "load-program"
	// CmdListName is the name of the list command
	CmdListName = "list"
	// CmdLsName is the name of the ls command
	CmdLsName = "ls"
	// CmdMarkName is the name of the mark command
	CmdMarkName = "mark"
	// CmdMayAliasName is the name of the mayalias command
	CmdMayAliasName = "mayalias"
	// CmdPackageName is the name of the function-pkg command
	CmdPackageName = "function-pkg"
	// CmdRebuildName is the name of the rebuild command
	CmdRebuildName = "rebuild"
	// CmdReconfigName is the name of the reconfig command
	CmdReconfigName = "reconfig"
	// CmdScanName is the name of the scan command
	CmdScanName = "scan"
	// CmdShowPackageName is the name of the showpkg command
	CmdShowPackageName = "showpkg"
	// CmdShowDataflowName is the name of the showdataflow command
	CmdShowDataflowName = "showdataflow"
	// CmdShowEscapeName is the name of the showescape command
	CmdShowEscapeName = "showescape"
	// CmdMembersName is the name of the members command
	CmdMembersName = "members"
	// CmdRunPointerName is the name of the run-pointer command
	CmdRunPointerName = "run-pointer"
	// CmdRunDataflowName is the name of the run-dataflow command
	CmdRunDataflowName = "run-dataflow"
	// CmdShowSsaName is the name of the showssa command
	CmdShowSsaName = "showssa"
	// CmdSrcName is the name of the src command
	CmdSrcName = "src"
	// CmdSsaInstrName is the name of the ssainstr command
	CmdSsaInstrName = "ssainstr"
	// CmdSsaValueName is the name of the ssaval command
	CmdSsaValueName = "ssaval"
	// CmdStateName is the name of the state? command
	CmdStateName = "state?"
	// CmdStatsName is the name of the stats command
	CmdStatsName = "stats"
	// CmdSummarizeName is the name of the summarize command
	CmdSummarizeName = "summarize"
	// CmdSummaryName is the name of the summary command
	CmdSummaryName = "summary"
	// CmdTaintName is the name of the taint command
	CmdTaintName = "taint"
	// CmdTraceName is the name of the trace command
	CmdTraceName = "trace"
	// CmdUnfocusName is the name of the unfocus command
	CmdUnfocusName = "unfocus"
	// CmdWhereName is the name of the where command
	CmdWhereName = "where"
	// Other constants

	// Summarize threshold puts a maximum size above which summary building filters are used
	summarizeThreshold = 5

	// MCP tool names
	toolAstName              = "argot_print_ast"
	toolBacktraceName        = "argot_dataflow_backtrace"
	toolBuildGraphName       = "argot_build_graph"
	toolCalleesName          = "argot_show_callees"
	toolCallersName          = "argot_show_callers"
	toolCdName               = "argot_system_cd"
	toolCheckName            = "argot_dataflow_check"
	toolExitName             = "argot_system_exit"
	toolFocusName            = "argot_function_focus"
	toolIntraName            = "argot_focused_intra"
	toolLoadName             = "argot_load"
	toolLoadPackagesName     = "argot_load_package"
	toolLoadWholeProgramName = "argot_load_program"
	toolListName             = "argot_list_functions"
	toolLsName               = "argot_system_ls"
	toolMarkName             = "argot_dataflow_mark"
	toolMayAliasName         = "argot_focused_mayalias"
	toolPackageName          = "argot_function_package"
	toolRebuildName          = "argot_program_rebuild"
	toolReconfigName         = "argot_reload_config"
	toolScanName             = "argot_scan"
	toolShowPackageName      = "argot_show_package"
	toolShowDataflowName     = "argot_show_dataflow"
	toolShowEscapeName       = "argot_show_escape"
	toolMembersName          = "argot_members"
	toolRunPointerName       = "argot_run_pointer"
	toolRunDataflowName      = "argot_run_dataflow"
	toolShowSsaName          = "argot_show_ssa"
	toolSrcName              = "argot_show_src"
	toolSsaInstrName         = "argot_show_ssa_instr"
	toolSsaValueName         = "argot_show_ssa_value"
	toolStateName            = "argot_show_state"
	toolStatsName            = "argot_show_stats"
	toolSummarizeName        = "argot_dataflow_summarize"
	toolSummaryName          = "argot_dataflow_summary"
	toolTaintName            = "argot_dataflow_taint"
	toolTraceName            = "argot_dataflow_trace"
	toolUnfocusName          = "argot_function_unfocus"
	toolWhereName            = "argot_where"
)

// ************ HELPERS *********

// NameAndLoc hold a name and location together
type NameAndLoc struct {
	name string
	loc  token.Position
}

func regexErr(o Outputter, expr string, err error) {
	o.WriteErr("Error while compiling %q into regex:", expr) // expr may come from config file
	o.WriteErr("  %s", err)                                  // err is safe
}
