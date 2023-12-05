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
	"maps"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// maxAccessPathLength bound the maximum length of an access path TODO: make this a config option
// this value does not affect soundness
const maxAccessPathLength = 4

type MarkWithPath struct {
	Mark       *Mark
	AccessPath string
}

type ValueWithPath struct {
	Value         ssa.Value
	Instruction   ssa.Instruction
	Path          string
	FromProcEntry bool
}

type AbstractValue struct {
	value        ssa.Value
	PathMappings map[string]map[*Mark]bool
}

func NewAbstractValue(v ssa.Value) *AbstractValue {
	return &AbstractValue{
		value: v, PathMappings: map[string]map[*Mark]bool{},
	}
}

func (a *AbstractValue) GetValue() ssa.Value {
	return a.value
}

func (a *AbstractValue) add(path string, mark *Mark) {
	if _, ok := a.PathMappings[path]; !ok {
		a.PathMappings[path] = map[*Mark]bool{}
	}
	a.PathMappings[path][mark] = true
}

// MarksAt returns all the marks on the abstract value for a certain path. For example, if the value is marked at
// ".field" by [m] and at "[*]" by [m'] then MarksAt(".field") will return "[m]" and MarksAt("[*]") will return "[m']".
// MarksAt("") will return [m,m']
// if the value is marked at "", by m”, then MarksAt(".field") will return "[m,m”]"
func (a *AbstractValue) MarksAt(path string) []MarkWithPath {
	if path == "" {
		return a.AllMarks()
	}
	marks := []MarkWithPath{}
	for p, m := range a.PathMappings {
		// Logic for matching paths
		relAccessPath, ok := strings.CutPrefix(p, path)
		if p == "" {
			relAccessPath = p
			ok = true
		}
		// If path matches, then add the marks with the right path
		if ok {
			for mark := range m {
				marks = append(marks, MarkWithPath{mark, relAccessPath})
			}
		}
	}
	return marks
}

func (a *AbstractValue) AllMarks() []MarkWithPath {
	if a == nil {
		return []MarkWithPath{}
	}
	var x []MarkWithPath
	for path, marks := range a.PathMappings {
		for mark := range marks {
			x = append(x, MarkWithPath{mark, path})
		}
	}
	return x
}

func (a *AbstractValue) mergeInto(b *AbstractValue) bool {
	if a == nil {
		return false
	}
	modified := false
	for path, aMarks := range a.PathMappings {
		if bMarks, ok := b.PathMappings[path]; !ok {
			b.PathMappings[path] = maps.Clone(aMarks)
			modified = true
		} else {
			for m := range aMarks {
				if !bMarks[m] {
					bMarks[m] = true
					modified = true
				}
			}
		}
	}
	return modified
}

func (a *AbstractValue) HasMarkAt(path string, m *Mark) bool {
	for _, m2 := range a.MarksAt(path) {
		if m2.Mark == m {
			return true
		}
	}
	return false
}

func (a *AbstractValue) Show(w io.Writer) {
	for path, marks := range a.PathMappings {
		fmt.Fprintf(w, "   %s = %s .%s marked by ", a.value.Name(), a.value, path)
		for mark := range marks {
			fmt.Fprintf(w, " <%s> ", mark)
		}
		fmt.Fprintf(w, "\n")
	}
}

func pathLen(path string) int {
	return 1 + strings.Count(path, "[*]") + strings.Count(path, ".")
}

func pathTrimLast(path string) string {
	if path == "" {
		return ""
	}
	if prefix, ok := strings.CutSuffix(path, "[*]"); ok {
		return prefix
	}
	n := strings.LastIndex(path, ".")
	if n > 0 {
		return path[n:]
	} else {
		return path
	}
}

func pathPrependField(path string, fieldName string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "." + fieldName + path
}

func pathPrependIndexing(path string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "[*]" + path
}

func pathAppendField(path string, fieldName string) string {
	if pathLen(path) > maxAccessPathLength {
		return path
	}
	return path + "." + fieldName
}

func pathAppendIndexing(path string) string {
	if pathLen(path) > maxAccessPathLength {
		return path
	}
	return path + "[*]"
}

func pathMatchField(path string, fieldName string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "."+fieldName)
}

func pathMatchIndex(path string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "[*]")
}
