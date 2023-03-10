package dataflow

import (
	"go/token"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// SourceType identifies different marks that can be propagated during the analysis.
// In the context of building function summaries, one can see the mark as a way to track where the data is flowing from.
// When running the taint analysis, the TaintedVal mark tracks tainted values.
// The design is open to the addition of other taint types.
type SourceType int

const (
	Parameter   SourceType = 1 << iota // A Parameter is a function parameter.
	FreeVar                            // A FreeVar is a free variable in a closure.
	TaintedVal                         // A TaintedVal is a value tainted by a taint source.
	CallSiteArg                        // A CallSiteArg is a call site argument.
	CallReturn                         // A CallReturn is a call site return.
	Closure                            // A Closure is a closure creation site
	BoundVar                           // A BoundVar is a variable bound by a closure
	Global                             // A Global is package global
	Synthetic                          // A Synthetic node type for any other node.
)

// Source is a node with additional information about its type and region path (matching the paths in pointer analysis)
type Source struct {
	Node       ssa.Node
	RegionPath string
	Type       SourceType
	Qualifier  ssa.Value
}

// DataFlows is a map from instructions to sets of instructions. We use this to represents data flows: if there
// are two instructions sink,source such that map[sink][source], then there is a data flow from source to sink.
type DataFlows = map[ssa.Instruction]map[ssa.Instruction]bool

// unionPaths is a utility function to merge two sets of instructions.
func unionPaths(p1 map[ssa.Instruction]bool, p2 map[ssa.Instruction]bool) map[ssa.Instruction]bool {
	for x, yb := range p2 {
		ya, ina := p1[x]
		if ina {
			p1[x] = yb || ya
		} else {
			p1[x] = yb
		}
	}
	return p1
}

// MergeDataFlows merges its two input DataFlows maps. When the function returns, the first argument contains
// all the entries in the second one.
// @requires a != nil
func MergeDataFlows(a DataFlows, b DataFlows) {
	for x, yb := range b {
		ya, ina := a[x]
		if ina {
			a[x] = unionPaths(ya, yb)
		} else {
			a[x] = yb
		}
	}
}

// NewSource creates a source with a single type
func NewSource(node ssa.Node, sourceType SourceType, path string) Source {
	return Source{
		Node:       node,
		RegionPath: path,
		Type:       sourceType,
		Qualifier:  nil,
	}
}

// NewQualifierSource creates a source with a single type and a qualifier node
func NewQualifierSource(node ssa.Node, qualifier ssa.Value, sourceType SourceType, path string) Source {
	return Source{
		Node:       node,
		RegionPath: path,
		Type:       sourceType,
		Qualifier:  qualifier,
	}
}

// IsTainted returns true if the source is a taint source.
func (s *Source) IsTainted() bool {
	return s.Type&TaintedVal != 0
}

// IsParameter returns true if the source is a function parameter.
func (s *Source) IsParameter() bool {
	return s.Type&Parameter != 0
}

// IsFreeVar returns true if the source is a closure free variable.
func (s *Source) IsFreeVar() bool {
	return s.Type&FreeVar != 0
}

// IsBoundVar returns true if the source is a closure free variable.
func (s *Source) IsBoundVar() bool {
	return s.Type&BoundVar != 0
}

// IsClosure returns true if the source is a closure
func (s *Source) IsClosure() bool {
	return s.Type&Closure != 0
}

// IsGlobal returns true if the source is a global
func (s *Source) IsGlobal() bool {
	return s.Type&Global != 0
}

// IsCallSiteArg returns true if the source is a call site argument. If it returns true, then s.qualifier must be
// non-nil.
func (s *Source) IsCallSiteArg() bool {
	return s.Type&CallSiteArg != 0
}

// IsCallReturn returns true if the source is a call return.
func (s *Source) IsCallReturn() bool {
	return s.Type&CallReturn != 0
}

// IsSynthetic returns true if the source is synthetic.
func (s *Source) IsSynthetic() bool {
	return s.Type&Synthetic != 0
}

// FlowInformation contains the information necessary for the analysis and function summary building.
type FlowInformation struct {
	Config         *config.Config                               // user provided configuration identifying sources and sinks
	MarkedValues   map[ssa.Value]map[Source]bool                // map from values to the set of sources that mark them
	MarkedPointers map[*pointer.Pointer]Source                  // map from pointer sets to the sources that mark them
	SinkSources    map[ssa.Instruction]map[ssa.Instruction]bool // map from the sinks to the set of sources that reach them
}

// NewFlowInfo returns a new FlowInformation with all maps initialized.
func NewFlowInfo(cfg *config.Config) *FlowInformation {
	return &FlowInformation{
		Config:         cfg,
		MarkedValues:   make(map[ssa.Value]map[Source]bool),
		MarkedPointers: make(map[*pointer.Pointer]Source),
		SinkSources:    make(map[ssa.Instruction]map[ssa.Instruction]bool),
	}
}

func (t *FlowInformation) HasSource(v ssa.Value, s Source) bool {
	sources, ok := t.MarkedValues[v]
	return ok && sources[s]
}

// AddSource adds a source to the tracking info structure and returns a boolean
// if new information has been inserted.
func (t *FlowInformation) AddSource(v ssa.Value, s Source) bool {
	if vSources, ok := t.MarkedValues[v]; ok {
		if vSources[s] {
			return false
		} else {
			vSources[s] = true
			return true
		}
	} else {
		t.MarkedValues[v] = map[Source]bool{s: true}
		return true
	}
}

func (t *FlowInformation) HasSinkSourcePair(sink ssa.Instruction, source ssa.Instruction) bool {
	sinkMap, ok := t.SinkSources[sink]
	return ok && sinkMap[source]
}

// AddSinkSourcePair adds a sink,source pair to the tracking info structure and returns a boolean
// if new information has been inserted.
func (t *FlowInformation) AddSinkSourcePair(sink ssa.Instruction, source ssa.Instruction) bool {
	if sinkMap, ok := t.SinkSources[sink]; ok {
		if sinkMap[source] {
			return false
		} else {
			sinkMap[source] = true
			return true
		}
	} else {
		t.SinkSources[sink] = map[ssa.Instruction]bool{source: true}
		return true
	}
}

// ReachedSinkPositions translated a DataFlows map in a program to a map from positions to set of positions,
// where the map associates sink positions to sets of source positions that reach it.
func ReachedSinkPositions(prog *ssa.Program, m DataFlows) map[token.Position]map[token.Position]bool {
	positions := make(map[token.Position]map[token.Position]bool)

	for sinkNode, sourceNodes := range m {
		sinkPos := sinkNode.Pos()
		sinkFile := prog.Fset.File(sinkPos)
		if sinkPos != token.NoPos && sinkFile != nil {
			positions[sinkFile.Position(sinkPos)] = map[token.Position]bool{}
			for sourceNode := range sourceNodes {
				sourcePos := sourceNode.Pos()
				sourceFile := prog.Fset.File(sourcePos)
				if sinkPos != token.NoPos && sourceFile != nil {
					positions[sinkFile.Position(sinkPos)][sourceFile.Position(sourcePos)] = true
				}
			}
		}
	}
	return positions
}
