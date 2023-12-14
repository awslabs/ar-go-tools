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

package reachability

import (
	"fmt"
	"log"
	"os"
	"sort"
)

// Entry is an entry of a dependency graph, containing the name of the package along with the packages its depends on
// and the packages that depend on it.
type Entry struct {
	name         string
	dependsOn    []*Entry
	dependedOnBy []*Entry
	visited      bool
	done         bool
}

// A DependencyGraph records package dependencies
type DependencyGraph map[string]*Entry

// NewDependencyGraph returns a new DependencyGraph
func NewDependencyGraph() DependencyGraph {
	return make(DependencyGraph)
}

func contains(list []*Entry, e *Entry) bool {
	for _, item := range list {
		if item == e {
			return true
		}
	}
	return false
}

// Add adds a dependency to the graph
func (dg DependencyGraph) Add(depender string, dependee string) {
	// get the entry for the depender. if none, add one
	e, ok := dg[depender]
	if !ok {
		e = &Entry{name: depender}
		dg[depender] = e
	}

	// now see if the dependee exists and create one if it doesn't
	d, ok := dg[dependee]
	if !ok {
		d = &Entry{name: dependee}
		dg[dependee] = d
	}

	// now see if this relation is already present
	if contains(e.dependsOn, d) {
		return // if a->b is present assume b<-a is too
	}
	// now add the dependency to the depender
	e.dependsOn = append(e.dependsOn, d)
	d.dependedOnBy = append(d.dependedOnBy, e)
}

// Cycles returns a boolean indicating whether there is a cycle in the graph or not
func (dg DependencyGraph) Cycles() bool {
	for _, e := range dg {
		if len(e.dependedOnBy) != 0 {
			continue
		}
		if dg.findCycles(e) {
			return true
		}
	}
	return false
}

func (dg DependencyGraph) findCycles(e *Entry) bool {
	if e.done {
		return false
	}
	if e.visited {
		fmt.Println("Found a cycle containing ", e.name)
		return true
	}
	e.visited = true
	defer func() { e.visited = false }()
	for _, d := range e.dependsOn {
		if dg.findCycles(d) {
			return true
		}
	}
	e.done = true
	return false
}

// DumpAsGraphviz dumps the graph in its graphviz format in the file with the name provided
func (dg DependencyGraph) DumpAsGraphviz(filename string, includeStdlib bool) {

	sum := 0
	for _, e := range dg {
		sum += len(e.dependsOn)
	}
	rows := make([]string, 0, sum)

	for source, entry := range dg {
		for _, target := range entry.dependsOn {
			rows = append(rows, fmt.Sprintf("\"%s\"->\"%s\"", source, target.name))
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i] < rows[j]
	})

	outfile, err := os.OpenFile(filename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	fmt.Fprint(outfile, "digraph dependency {\n")
	for _, entry := range rows {
		fmt.Fprintf(outfile, "\t%s\n", entry)
	}
	fmt.Fprint(outfile, "}")

}
