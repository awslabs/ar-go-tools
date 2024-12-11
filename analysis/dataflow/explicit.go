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
	"strconv"
	"strings"
)

// A VisitorKind should be either DefaultTracing or ClosureTracing and defines the behaviour of the Visitor
type VisitorKind int

const (
	// DefaultTracing is for the default dataflow analysis mode
	DefaultTracing VisitorKind = 1 << iota
	// ClosureTracing denotes the mode where the visitor is used to follow a closure
	ClosureTracing
)

func (v VisitorKind) String() string {
	switch v {
	case DefaultTracing:
		return "DefaultTracing"
	case ClosureTracing:
		return "ClosureTracing"
	default:
		panic(fmt.Errorf("invalid VisitorKind: %d", v))
	}
}

type closureTracingInfo struct {
	prev                *closureTracingInfo
	Index               int
	ClosureSummaryGraph *SummaryGraph
}

// Next implements iteration
func (c *closureTracingInfo) Next(summary *SummaryGraph, index int) *closureTracingInfo {
	return &closureTracingInfo{
		prev:                c,
		Index:               index,
		ClosureSummaryGraph: summary,
	}
}

// VisitorNodeStatus represents the status of a visitor node. It is either in default mode, in which case
// the Index does not mean anything, or it is in ClosureTracing mode, in which case the index represents the index of
// the bound variable that needs to be traced to a closure call.
type VisitorNodeStatus struct {
	Kind        VisitorKind
	TracingInfo *closureTracingInfo
}

// CurrentClosure returns the closure being currently traces by the node status
func (v VisitorNodeStatus) CurrentClosure() *SummaryGraph {
	if v.TracingInfo == nil {
		return nil
	}
	return v.TracingInfo.ClosureSummaryGraph
}

// PopClosure pops the current closure from the stack of closures being traces
func (v VisitorNodeStatus) PopClosure() VisitorNodeStatus {
	switch v.Kind {
	case DefaultTracing:
		return v
	case ClosureTracing:
		if v.TracingInfo == nil {
			return VisitorNodeStatus{
				Kind:        DefaultTracing,
				TracingInfo: nil,
			}
		}
		prevTracingInfo := v.TracingInfo.prev
		if prevTracingInfo == nil {
			return VisitorNodeStatus{
				Kind:        DefaultTracing,
				TracingInfo: nil,
			}
		}
		return VisitorNodeStatus{
			Kind:        ClosureTracing,
			TracingInfo: prevTracingInfo,
		}
	}
	return VisitorNodeStatus{
		Kind:        DefaultTracing,
		TracingInfo: nil,
	}
}

func (v VisitorNodeStatus) String() string {
	return fmt.Sprintf("Kind: %v, TracingInfo: %v", v.Kind, v.TracingInfo)
}

// VisitorNode represents a node in the inter-procedural dataflow graph to be visited.
type VisitorNode struct {
	NodeWithTrace
	Prev        *VisitorNode
	Depth       int
	AccessPaths []string
	Status      VisitorNodeStatus
	children    []*VisitorNode
}

// Key returns a unique string representation for the node with its trace
func (v *VisitorNode) Key() KeyType {
	return v.NodeWithTrace.Key() + "_" + strconv.Itoa(int(v.Status.Kind)) + "." + strings.Join(v.AccessPaths, "|")
}

// AddChild adds a child to the node
func (v *VisitorNode) AddChild(c *VisitorNode) {
	v.children = append(v.children, c)
}

// ParamStack represents a stack of parameters.
type ParamStack struct {
	Param *ParamNode
	Prev  *ParamStack
}
