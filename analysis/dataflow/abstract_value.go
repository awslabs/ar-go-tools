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
	"io"

	"golang.org/x/tools/go/ssa"
)

type MarkWithPath struct {
	Mark Mark
	Path string
}

type ValueWithPath struct {
	Value ssa.Value
	Path  string
}

type abstractValue struct {
	value        ssa.Value
	PathMappings map[string]map[Mark]bool
}

func newAbstractValue(v ssa.Value) abstractValue {
	return abstractValue{
		value: v, PathMappings: map[string]map[Mark]bool{},
	}
}

func (a abstractValue) Add(path string, mark Mark) {
	if _, ok := a.PathMappings[path]; !ok {
		a.PathMappings[path] = map[Mark]bool{}
	}
	a.PathMappings[path][mark] = true
}

func (a abstractValue) MarksAt(path string) map[Mark]bool {
	return a.PathMappings[path]
}

func (a abstractValue) AllMarks() []MarkWithPath {
	x := []MarkWithPath{}
	for path, marks := range a.PathMappings {
		for mark := range marks {
			x = append(x, MarkWithPath{mark, path})
		}
	}
	return x
}

func (a abstractValue) HasMarkAt(path string, m Mark) bool {
	marks, ok := a.PathMappings[path]
	return ok && marks[m]
}

func (a abstractValue) Show(w io.Writer) {
	for path, marks := range a.PathMappings {
		fmt.Fprintf(w, "   %s = %s .%s marked by ", a.value.Name(), a.value, path)
		for mark := range marks {
			fmt.Fprintf(w, " <%s> ", &mark)
		}
		fmt.Fprintf(w, "\n")
	}
}
