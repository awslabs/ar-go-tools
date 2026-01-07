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
	"context"

	"github.com/awslabs/ar-go-tools/analysis/check"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	checkCmd "github.com/awslabs/ar-go-tools/cmd/argot/check"
)

// cmdCheck checks a dataflow summary
func cmdCheck(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : check if a dataflow summary is sound (within the context of a particular program)"+
			"\n", o.EscBlue(), CmdCheckName, o.EscReset())
		o.Write("\t   The summaries are loaded from the config-specified user-specs file. The file is \n" +
			"read when the command is run.\n")
		o.Write("\t   regex the argument will filter by summary name\n")
		o.Write("\t   -force flag will force summarization and bypass filters on reachable functions.\n")
		return false
	}
	state, err := sess.loadDataflowAnalysis(o).Value()
	if err != nil {
		o.WriteErr("Error: %v\n", err)
		return false
	}
	ctx := context.Background()
	filter := ""
	if len(command.Args) > 0 {
		filter = command.Args[0]
	}
	summaries, err2 := checkCmd.ParseSummaries(state.Config, state.Logger, filter)
	if err2 != nil {
		o.WriteErr("Error: %v\n", err2)
		return false
	}
	var specs []dataflow.ScanningSpec
	if targetName, ok := command.NamedArgs["target"]; ok {
		specs = dataflow.GetScanningSpecs(state, targetName)
	} else if sess.target != "" {
		specs = dataflow.GetScanningSpecs(state, sess.target)
	}
	_, err = checkCmd.SummariesWithSpecs(ctx, state, summaries, check.All, specs)
	if err != nil {
		o.WriteErr("Error: %v\n", err)
		return false
	}
	return false
}
