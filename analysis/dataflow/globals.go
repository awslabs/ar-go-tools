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
	"go/types"
	"sync"

	"golang.org/x/tools/go/ssa"
)

func newGlobalNode(g *ssa.Global) *GlobalNode {
	return &GlobalNode{
		mutex:          &sync.Mutex{},
		value:          g,
		WriteLocations: map[GraphNode]bool{},
		ReadLocations:  map[GraphNode]bool{},
	}
}

// GlobalNode represents a global in the dataflow analysis. Operating on globals requires locking when analyzing
// functions in parallel
type GlobalNode struct {
	mutex          *sync.Mutex
	value          *ssa.Global
	WriteLocations map[GraphNode]bool
	ReadLocations  map[GraphNode]bool
}

func (g *GlobalNode) addWriteLoc(n GraphNode) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.WriteLocations[n] = true
}

func (g *GlobalNode) addReadLoc(n GraphNode) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.ReadLocations[n] = true
}

func (g *GlobalNode) String() string {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return fmt.Sprintf("\"defglobal: %s\"", g.value.String())
}

// Type returns the type of the global
func (g *GlobalNode) Type() types.Type {
	if g == nil || g.value == nil {
		return nil
	}
	return g.value.Type()
}

// Value returns the ssa value of the node
func (g *GlobalNode) Value() ssa.Value {
	return g.value
}
