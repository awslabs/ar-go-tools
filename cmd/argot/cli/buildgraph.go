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

// cmdBuildGraph builds the inter-procedural flow graph given the current summaries
func cmdBuildGraph(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : build the inter-procedural flow graph.\n",
			o.EscBlue(), CmdBuildGraphName, o.EscReset())
		o.Write("\t   Summaries must be built first with `%s%s%s`.\n",
			o.EscYellow(), CmdSummarizeName, o.EscReset())
		return false
	}
	c, err := sess.loadDataflowAnalysis(o).Value()
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	if len(c.FlowGraph.Summaries) == 0 {
		o.WriteErr("No summaries present. Did you run `summarize`?")
		return false
	}
	c.FlowGraph.BuildGraph()
	o.WriteSuccess("Built cross function flow graph.")
	return false
}
