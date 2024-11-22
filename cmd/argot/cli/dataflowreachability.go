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
	"regexp"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"golang.org/x/term"
)

// cmdTrace runs a taint-like analysis, but starting from a custom node
func cmdTrace(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: show information about nodes reachable from another node using data edges.\n",
			tt.Escape.Blue, cmdTraceName, tt.Escape.Reset)
		writeFmt(tt, "\t    Argument is a regex matching node ids.\n")
		writeFmt(tt, "\t    -h    print this help message\n")

		return false
	}

	if !c.FlowGraph.IsBuilt() {
		WriteErr(tt, "The inter-procedural dataflow graph is not built!")
		WriteErr(tt, "Please run `%s` before calling `trace`.", cmdBuildGraphName)
		return false
	}

	if len(command.Args) < 1 {
		WriteErr(tt, "Missing one positional argument for %s.", cmdTraceName)
		return false
	}
	r, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}
	preLevel := c.Logger.Level

	if command.Flags["t"] {
		c.Logger.Level = config.TraceLevel
	}
	dummyTaintSpec := &config.TaintSpec{}
	scanningSpec := dataflow.ScanningSpec{
		IsEntryPointGraph: func(g dataflow.GraphNode) bool { return r.MatchString(g.LongID()) },
	}
	c.FlowGraph.RunVisitorOnEntryPoints(taint.NewVisitor(dummyTaintSpec), scanningSpec)

	c.Logger.Level = preLevel
	return false
}
