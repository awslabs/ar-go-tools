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
	"strconv"

	"golang.org/x/tools/go/ssa"
)

// MarkType identifies different marks that can be propagated during the analysis.
// In the context of building function summaries, one can see the mark as a way to track where the data is flowing from.
// When running the taint analysis, the DefaultMark mark tracks tainted values.
// The design is open to the addition of other taint types.
type MarkType int

const (
	// Parameter is a function parameter.
	Parameter MarkType = 1 << iota
	// FreeVar is a free variable in a closure.
	FreeVar
	// DefaultMark is a Value with a mark.
	DefaultMark
	// CallSiteArg is a call site argument.
	CallSiteArg
	// CallReturn is a call site return.
	CallReturn
	// Closure is a closure creation site
	Closure
	// BoundVar is a variable bound by a closure
	BoundVar
	// Global is package global
	Global
	// Synthetic node type for any other node.
	Synthetic
	// If is an if statement.
	If
)

// IndexKind qualifies the kind of index of mark. It is either the index on a value returned by a function,
// or not an actual index.
type IndexKind int

const (
	// NonIndex is the kind of non-indices
	NonIndex IndexKind = iota
	// ReturnedTupleIndex is the kind of indices on tuples returned by functions
	ReturnedTupleIndex
)

func (m MarkType) String() string {
	switch m {
	case Parameter:
		return "parameter"
	case FreeVar:
		return "freevar"
	case DefaultMark:
		return "default"
	case CallSiteArg:
		return "arg"
	case CallReturn:
		return "call"
	case Closure:
		return "closure"
	case BoundVar:
		return "boundvar"
	case Global:
		return "global"
	case Synthetic:
		return "synthetic"
	case If:
		return "if"
	default:
		return "multiple"
	}
}

// MarkIndex wraps an index kind and the index value together
type MarkIndex struct {
	// Kind is the kind of index (currently, either a real index or not)
	Kind IndexKind
	// Value is the integer value of the index
	Value int
}

// NonIndexMark is the instance of the non-index of type MarkIndex
var NonIndexMark = MarkIndex{Kind: NonIndex, Value: -1}

// NewIndex returns a new MarkIndex of type ReturnedTupleIndex and with the value provided.
func NewIndex(index int) MarkIndex {
	return MarkIndex{Kind: ReturnedTupleIndex, Value: index}
}

// Mark is a node with additional information about its type and region Path (matching the paths in pointer analysis).
// This is used to mark dataflow between nodes.
type Mark struct {
	// Node is the ssa node that the mark is tracking
	Node ssa.Node

	// MarkType is the type of the mark
	Type MarkType

	// Qualifier gives more information about which sub-Value of the current ssa Value is referred to by this mark
	Qualifier ssa.Value

	// Index specifies an index of the tuple element referred to by this mark. Node's type must be a tuple.
	// A Value of -1 indicates this can be ignored
	Index MarkIndex

	// Label holds additional information about the mark, for example the original access path relative to the
	// parameter the mark is tracking
	Label string
}

// NewMark creates a source with a single type. Using this as constructor enforces that users provide an explicit
// Value for index, whose default Value has a meaning that might not be intended
func NewMark(node ssa.Node, typ MarkType, qualifier ssa.Value, index MarkIndex, label string) Mark {
	return Mark{
		Node:      node,
		Type:      typ,
		Qualifier: qualifier,
		Index:     index,
		Label:     label,
	}
}

// IsDefault returns true if the source is a taint source.
func (m Mark) IsDefault() bool {
	return m.Type&DefaultMark != 0
}

// IsParameter returns true if the source is a function parameter.
func (m Mark) IsParameter() bool {
	return m.Type&Parameter != 0
}

// IsFreeVar returns true if the source is a closure free variable.
func (m Mark) IsFreeVar() bool {
	return m.Type&FreeVar != 0
}

// IsBoundVar returns true if the source is a closure free variable.
func (m Mark) IsBoundVar() bool {
	return m.Type&BoundVar != 0
}

// IsClosure returns true if the source is a closure
func (m Mark) IsClosure() bool {
	return m.Type&Closure != 0
}

// IsGlobal returns true if the source is a global
func (m Mark) IsGlobal() bool {
	return m.Type&Global != 0
}

// IsCallSiteArg returns true if the source is a call site argument. If it returns true, then s.qualifier must be
// non-nil.
func (m Mark) IsCallSiteArg() bool {
	return m.Type&CallSiteArg != 0
}

// IsCallReturn returns true if the source is a call return.
func (m Mark) IsCallReturn() bool {
	return m.Type&CallReturn != 0
}

// IsSynthetic returns true if the source is synthetic.
func (m Mark) IsSynthetic() bool {
	return m.Type&Synthetic != 0
}

// IsIf returns true if the source is an if condition.
func (m Mark) IsIf() bool {
	return m.Type&If != 0
}

func (m Mark) String() string {
	str := m.Type.String() + ": "
	if m.Qualifier != nil {
		str += m.Qualifier.Name() + " in "
	}
	str += m.Node.String()
	if m.Index.Kind == ReturnedTupleIndex {
		str += " #" + strconv.Itoa(m.Index.Value)
	}
	if m.Label != "" {
		str += "(" + m.Label + ")"
	}
	return "🏷 " + str
}
