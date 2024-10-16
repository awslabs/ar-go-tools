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
	"io"
	"strings"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/shims"
	"golang.org/x/tools/go/ssa"
)

// maxAccessPathLength bound the maximum length of an access path TODO: make this a config option
// this value does not affect soundness
var maxAccessPathLength = 3

// SetMaxAccessPathLength sets the maximum access path length for field sensitivity. This should only be set once,
// changing this value while the analysis is running may lead to unpredictable results.
func SetMaxAccessPathLength(n int) {
	maxAccessPathLength = n
}

// A MarkWithAccessPath is a mark with an access path
type MarkWithAccessPath struct {
	Mark       *Mark
	AccessPath string
}

// InstructionValueWithAccessPath represents a value at an instruction with a specific access path. The boolean
// FromProcEntry is used by some functions to differentiate how the value was collected.
type InstructionValueWithAccessPath struct {
	Value       ssa.Value
	Instruction ssa.Instruction
	Path        string
}

// A ValueWithAccessPath is a value with an access path, e.g. a value "x" with an access path ".field1" represents
// member field1 of the struct x.
type ValueWithAccessPath struct {
	Value ssa.Value
	Path  string
}

// An AbstractValue represents an abstract value in the dataflow computation algorithm: an abstract value is an SSA
// value with a set of marks.
// If the value is represented in an (access-)path sensitive manner, then isPathSensitive must be true and the
// maps of accessMarks is in use.
// If the value is not (access-)path sensitive, the marks maps is the set of marks of that value.
type AbstractValue struct {
	// value is the SSA value represented by that abstract value
	value ssa.Value

	// isPathSensitive indicates whether that value is represented in a path sensitive manner
	isPathSensitive bool

	// marks is the set of marks of the value when !isPathSensitive
	marks map[*Mark]bool

	// accessMarks is the set of marks with the relative path when isPathSensitive
	accessMarks map[string]map[*Mark]bool
}

// NewAbstractValue returns a new abstract value v. If pathSensitive is true, then the abstract value is represented
// in an access path sensitive manner (marks on the value are different depending on the access path).
func NewAbstractValue(v ssa.Value, pathSensitive bool) *AbstractValue {
	if pathSensitive {
		return &AbstractValue{
			value:           v,
			accessMarks:     map[string]map[*Mark]bool{},
			marks:           nil,
			isPathSensitive: true,
		}
	}
	return &AbstractValue{
		value:           v,
		accessMarks:     nil,
		marks:           map[*Mark]bool{},
		isPathSensitive: false,
	}
}

// PathMappings returns a map from access path to set of marks. If the abstract value is no access-path (or field)
// sensitive, then the only access path is "".
func (a *AbstractValue) PathMappings() map[string]map[*Mark]bool {
	if a.isPathSensitive {
		return a.accessMarks
	}
	return map[string]map[*Mark]bool{"": a.marks}
}

// GetValue returns the ssa value of the abstract value.
func (a *AbstractValue) GetValue() ssa.Value {
	return a.value
}

// add adds a mark relative to a certain path (ignored if the abstract value is not access-path sensitive).
func (a *AbstractValue) add(path string, mark *Mark) {
	if a.isPathSensitive {
		if _, ok := a.accessMarks[path]; !ok {
			a.accessMarks[path] = map[*Mark]bool{}
		}
		a.accessMarks[path][mark] = true
	} else {
		a.marks[mark] = true
	}
}

// MarksAt returns all the marks with relative paths on the abstract value for a certain path.
// For example, if the value x is marked at  ".field" by [m] and at "[*]" by [m'] then x.MarksAt(".field") will return
// "[{m,""}]"  and x.MarksAt("[*]") will return "[{m',""}]". x.MarksAt("") will return [{m,".field"},{m',"[*]"}]
//
// - If the value is marked at "", by "m”, then MarksAt(".field") will return "[{m, ""},{"m'”,""}]".
//
// - if the value z is marked at ".f.g" by "o", then z.MarksAt(".f") will return [{m, ".g"}]
//
// If the value is not path sensitive, then MarkAt simply returns AllMarks(), the path is ignored.
//
// TODO: the implementation of access paths will change, and we will provide a more complete documentation then.
func (a *AbstractValue) MarksAt(path string) []MarkWithAccessPath {
	if path == "" || !a.isPathSensitive {
		return a.AllMarks()
	}
	marks := []MarkWithAccessPath{}
	for p, m := range a.accessMarks {
		// Logic for matching paths
		relAccessPath, ok := strings.CutPrefix(p, path)
		if p == "" {
			relAccessPath = p
			ok = true
		}
		// If path matches, then add the marks with the right path
		if ok {
			for mark := range m {
				marks = append(marks, MarkWithAccessPath{mark, relAccessPath})
			}
		}
	}
	return marks
}

// AllMarks returns all the marks on the abstract value, ignoring their access path.
func (a *AbstractValue) AllMarks() []MarkWithAccessPath {
	if a == nil {
		return []MarkWithAccessPath{}
	}
	var x []MarkWithAccessPath
	if a.isPathSensitive {
		for path, marks := range a.accessMarks {
			for mark := range marks {
				x = append(x, MarkWithAccessPath{mark, path})
			}
		}
	} else {
		for mark := range a.marks {
			x = append(x, MarkWithAccessPath{mark, ""})
		}
	}
	return x
}

// mergeInto merges the information in a into b.
// a is not modified, and the boolean returned indicates whether b has been modified or not.
//
//gocyclo:ignore
func (a *AbstractValue) mergeInto(b *AbstractValue) bool {
	if a == nil {
		return false
	}
	modified := false
	if a.isPathSensitive {
		if b.isPathSensitive {
			// merge a path-sensitive value into a path-sensitive one
			// paths need to be transferred
			for path, aMarks := range a.accessMarks {
				if bMarks, ok := b.accessMarks[path]; !ok {
					b.accessMarks[path] = shims.Clone(aMarks)
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
		} else {
			// merge into a non-access-path-sensitive value
			// access path information gets lost
			for _, m := range a.AllMarks() {
				if !b.marks[m.Mark] {
					modified = true
					b.marks[m.Mark] = true
				}
			}
		}
	} else {
		if b.isPathSensitive {
			// transfer the marks of a to the root of b (path "")
			for mark := range a.marks {
				if bRootMapping, ok := b.accessMarks[""]; !ok {
					b.accessMarks[""] = map[*Mark]bool{mark: true}
				} else if !bRootMapping[mark] {
					modified = true
					b.accessMarks[""][mark] = true
				}
			}
		} else {
			// both a not path-sensitive
			for mark := range a.marks {
				if !b.marks[mark] {
					b.marks[mark] = true
					modified = true
				}
			}
		}
	}
	return modified
}

// HasMarkAt returns a boolean indicating whether the abstractValue has a mark at the given path.
func (a *AbstractValue) HasMarkAt(path string, m *Mark) bool {
	if !a.isPathSensitive {
		return a.marks[m]
	}
	for _, m2 := range a.MarksAt(path) {
		if m2.Mark == m {
			return true
		}
	}
	return false
}

// Show writes information about the value on the writer
func (a *AbstractValue) Show(w io.Writer) {
	if !a.isPathSensitive {
		for mark := range a.marks {
			fmt.Fprintf(w, "   %s = %s marked by <%s>", a.value.Name(), a.value,
				formatutil.Sanitize(mark.String()))
		}
	} else {
		for path, marks := range a.accessMarks {
			fmt.Fprintf(w, "   %s = %s .%s marked by ", a.value.Name(), a.value, path)
			for mark := range marks {
				fmt.Fprintf(w, " <%s> ", mark)
			}
			fmt.Fprintf(w, "\n")
		}
	}
}

// AccessPathsOfType returns a slice of all the possible access paths that can be used on a value of type t.
// For example, on a value of type struct{A: map[T]S, B: string} the possible access paths are
// ".A", ".B", ".A[*]"
func AccessPathsOfType(t types.Type) []string {
	return boundedAccessPathsOfType(t, maxAccessPathLength)
}

//gocyclo:ignore
func boundedAccessPathsOfType(t types.Type, n int) []string {
	if n <= 0 {
		return []string{}
	}
	switch actualType := t.(type) {
	case *types.Pointer:
		return boundedAccessPathsOfType(actualType.Elem(), n)
	case *types.Named:
		return boundedAccessPathsOfType(actualType.Underlying(), n)
	case *types.Array:
		accessPaths := boundedAccessPathsOfType(actualType.Elem(), n-1)
		for i, aPath := range accessPaths {
			accessPaths[i] = accessPathPrependIndexing(aPath)
		}
		if len(accessPaths) == 0 {
			accessPaths = append(accessPaths, accessPathPrependIndexing(""))
		}
		return accessPaths
	case *types.Slice:
		accessPaths := boundedAccessPathsOfType(actualType.Elem(), n-1)
		for i, aPath := range accessPaths {
			accessPaths[i] = accessPathPrependIndexing(aPath)
		}
		if len(accessPaths) == 0 {
			accessPaths = append(accessPaths, accessPathPrependIndexing(""))
		}
		return accessPaths
	case *types.Map:
		accessPaths := boundedAccessPathsOfType(actualType.Elem(), n-1)
		for i, aPath := range accessPaths {
			accessPaths[i] = accessPathPrependIndexing(aPath)
		}
		if len(accessPaths) == 0 {
			accessPaths = append(accessPaths, accessPathPrependIndexing(""))
		}
		return accessPaths
	case *types.Struct:
		var accessPaths []string
		for fieldNum := 0; fieldNum < actualType.NumFields(); fieldNum++ {
			field := actualType.Field(fieldNum)
			fieldAccessPaths := boundedAccessPathsOfType(field.Type(), n-1)
			if len(fieldAccessPaths) > 0 {
				for i, aPath := range fieldAccessPaths {
					fieldAccessPaths[i] = accessPathPrependField(aPath, field.Name(), field.Embedded())
				}
				accessPaths = append(accessPaths, fieldAccessPaths...)
			}
			if len(fieldAccessPaths) == 0 {
				accessPaths = append(accessPaths, accessPathPrependField("", field.Name(), field.Embedded()))
			}

		}
		return accessPaths
	}
	return []string{}
}

// accessPathLen returns the length of the path in terms of object "accesses"
func accessPathLen(path string) int {
	return 1 + strings.Count(path, "[*]") + strings.Count(path, ".")
}

// pathTrimLast removes the last element of the path
func pathTrimLast(path string) string {
	if path == "" {
		return ""
	}
	if prefix, ok := strings.CutSuffix(path, "[*]"); ok {
		return prefix
	}
	n := strings.LastIndex(path, ".")
	if n > 0 {
		return path[:n]
	}
	return path
}

func accessPathPrepend(path string, element string) string {
	if accessPathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return element + path
}

// accessPathPrependField prefixes the path with a field access
func accessPathPrependField(path string, fieldName string, embedded bool) string {
	if fieldName == "" || embedded {
		// ignore empty or embedded fields in path tracking. The data will never be accessed with the embedded field in
		// the path
		return path
	}
	return accessPathPrepend(path, "."+fieldName)
}

// accessPathPrependIndexing prefixes the path with an indexing operation
func accessPathPrependIndexing(path string) string {
	return accessPathPrepend(path, "[*]")
}

// accessPathMatchField checks whether path starts with the field fieldName.
// For example, accessPathMatchField(".field1.field2", "field1") is ".field2", true
// and accessPathMatchField(".field2.field1", "field1") is "field2.field1", false.
// / If path is empty, always returns true.
func accessPathMatchField(path string, fieldName string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "."+fieldName)
}

// accessPathMatchIndex checks whether path start with some indexing and returns the suffix
// and true if it does start with indexing. Otherwise, the entire path is returned with
// false.
func accessPathMatchIndex(path string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "[*]")
}
