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
	"strings"

	"golang.org/x/tools/go/ssa"
)

// maxAccessPathLength bound the maximum length of an access path TODO: make this a config option
// this value does not affect soundness
const maxAccessPathLength = 4

type MarkWithPath struct {
	Mark       Mark
	AccessPath string
}

type ValueWithPath struct {
	Value         ssa.Value
	Instruction   ssa.Instruction
	Path          string
	FromProcEntry bool
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

func (a abstractValue) add(path string, mark Mark) {
	if _, ok := a.PathMappings[path]; !ok {
		a.PathMappings[path] = map[Mark]bool{}
	}
	a.PathMappings[path][mark] = true
}

// MarksAt returns all the marks on the abstract value for a certain path. For example, if the value is marked at
// ".field" by [m] and at "[*]" by [m'] then MarksAt(".field") will return "[m]" and MarksAt("[*]") will return "[m']".
// MarksAt("") will return [m,m']
// if the value is marked at "", by m”, then MarksAt(".field") will return "[m,m”]"
func (a abstractValue) MarksAt(path string) map[MarkWithPath]bool {
	marks := map[MarkWithPath]bool{}
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
				marks[MarkWithPath{mark, relAccessPath}] = true
			}
		}
	}
	return marks
}

func (a abstractValue) AllMarks() []MarkWithPath {
	var x []MarkWithPath
	for path, marks := range a.PathMappings {
		for mark := range marks {
			x = append(x, MarkWithPath{mark, path})
		}
	}
	return x
}

func (a abstractValue) HasMarkAt(path string, m Mark) bool {
	for m2 := range a.MarksAt(path) {
		if m2.Mark == m {
			return true
		}
	}
	return false
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

func pathAddField(path string, fieldName string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "." + fieldName + path
}

func pathAddIndexing(path string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "[*]" + path
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
