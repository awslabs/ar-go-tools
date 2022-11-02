package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"go/token"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// SourceType identifies different taints that can be propagated during the analysis.
// The design is open to the addition of other taint types.
type SourceType int

const (
	FormalArg SourceType = 1 << iota
	TaintedVal
)

// SourceTypeIndex tracks the index of a given source type in the Source.Nodes of a Source
type SourceTypeIndex int

const (
	FormalArgIndex SourceTypeIndex = iota
	TaintedValIndex
)

type Source struct {
	Nodes [2]ssa.Instruction
	Path  string
	Type  SourceType
}

// NewSource creates a source with a single type
func NewSource(node ssa.Instruction, sourceType SourceType, path string) *Source {
	source := &Source{
		Nodes: [2]ssa.Instruction{},
		Path:  path,
		Type:  sourceType,
	}
	switch sourceType {
	case FormalArg:
		source.Nodes[FormalArgIndex] = node
	case TaintedVal:
		source.Nodes[TaintedValIndex] = node
	}
	return source
}

func (s *Source) IsTainted() bool {
	return s.Type&TaintedVal != 0
}

func (s *Source) GetTaintSourceInstruction() ssa.Instruction {
	return s.Nodes[TaintedValIndex]
}

func (s *Source) IsFormalArg() bool {
	return s.Type&FormalArg != 0
}

type TrackingInfo struct {
	config          *config.Config
	taintedValues   map[ssa.Value]*Source
	taintedPointers map[*pointer.PointsToSet]*Source
	SinkFromSource  map[ssa.Instruction]ssa.Instruction
}

type taintTracker struct {
	trackingInfo *TrackingInfo
	pointerInfo  *pointer.Result
	changeFlag   bool
	blocksSeen   map[*ssa.BasicBlock]struct{}
}

func (t TrackingInfo) ReachedSinkPositions(prog *ssa.Program) map[token.Position]token.Position {
	positions := make(map[token.Position]token.Position)

	for sinkNode, sourceNode := range t.SinkFromSource {
		sinkPos := sinkNode.Pos()
		sourcePos := sourceNode.Pos()
		if sinkPos != token.NoPos && sourcePos != token.NoPos {
			sinkFile := prog.Fset.File(sinkPos)
			sourceFile := prog.Fset.File(sourcePos)
			if sinkFile != nil && sourceFile != nil {
				positions[sinkFile.Position(sinkPos)] = sinkFile.Position(sourcePos)
			}
		}
	}
	return positions
}
