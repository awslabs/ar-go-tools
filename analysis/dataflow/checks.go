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

package dataflow

import (
	"fmt"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// CheckIndex checks that the indexed graph node is valid in the parent node call site
func CheckIndex(c *State, node IndexedGraphNode, callSite *CallNode, msg string) error {
	if node.Index() >= len(callSite.Args()) {
		pos := c.Program.Fset.Position(callSite.CallSite().Value().Pos())
		c.Logger.Debugf("%s: trying to access index %d of %s, which has"+
			" only %d elements\nSee: %s\n", msg, node.Index(), callSite, len(callSite.Args()),
			pos)
		return fmt.Errorf("bad index %d at %s", node.Index(), pos)
	}
	return nil
}

// CheckClosureReturns returns true if returnNode's summary is the same as closureNode's.
func CheckClosureReturns(returnNode *ReturnValNode, closureNode *ClosureNode) bool {
	return returnNode.Graph() == closureNode.ClosureSummary
}

// CheckNoGoRoutine logs a message if node's callsite is a goroutine.
func CheckNoGoRoutine(s *State, reportedLocs map[*ssa.Go]bool, node *CallNode) {
	if s.Config.UseEscapeAnalysis {
		return // escape analysis will handle any unsoundness, so there is no need to report
	}

	if goroutine, isGo := node.CallSite().(*ssa.Go); isGo {
		if !reportedLocs[goroutine] {
			reportedLocs[goroutine] = true
			s.Logger.Warnf(formatutil.Yellow("Data flows to Go call."))
			s.Logger.Warnf("-> Position: %s", node.Position(s))
		}
	}
}
