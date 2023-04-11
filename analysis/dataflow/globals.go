package dataflow

import (
	"fmt"
	"go/types"
	"sync"

	"golang.org/x/tools/go/ssa"
)

func NewGlobalNode(g *ssa.Global) *GlobalNode {
	return &GlobalNode{
		mutex:          &sync.Mutex{},
		value:          g,
		WriteLocations: map[GraphNode]bool{},
		ReadLocations:  map[GraphNode]bool{},
	}
}

type GlobalNode struct {
	mutex          *sync.Mutex
	value          *ssa.Global
	WriteLocations map[GraphNode]bool
	ReadLocations  map[GraphNode]bool
}

func (g *GlobalNode) AddWriteLoc(n GraphNode) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.WriteLocations[n] = true
}

func (g *GlobalNode) AddReadLoc(n GraphNode) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.ReadLocations[n] = true
}

func (g *GlobalNode) String() string {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return fmt.Sprintf("\"defglobal: %s\"", g.value.String())
}

func (g *GlobalNode) Type() types.Type {
	if g == nil || g.value == nil {
		return nil
	}
	return g.value.Type()
}
