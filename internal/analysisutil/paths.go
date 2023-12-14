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

package analysisutil

import (
	"os"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// MakeAbsolute takes a slice of relative file paths and converts them to absolute paths.
// It prepends the current working directory to any non-absolute file paths.
//
// excludeRelative is a slice of relative or absolute file paths to convert.
//
// It returns a new slice containing the absolute paths.
// Any paths that were already absolute are passed through unchanged.
//
// It returns an error if it cannot determine the current working directory.
// The result slice may have a different capacity and length than the input.
func MakeAbsolute(excludeRelative []string) []string {
	result := make([]string, 0, len(excludeRelative))

	cwd, _ := os.Getwd()

	for _, s := range excludeRelative {
		var excludeAbsolute string
		if strings.HasPrefix(s, "/") {
			excludeAbsolute = s
		} else {
			excludeAbsolute = cwd + "/" + s
		}
		result = append(result, excludeAbsolute)
	}

	return result
}

func isExcludedOne(program *ssa.Program, f *ssa.Function, exclude string) bool {
	pos := f.Pos()
	position := program.Fset.Position(pos)
	filename := position.Filename

	if strings.HasSuffix(exclude, ".go") {
		return filename == exclude // full match required
	} else if strings.HasSuffix(exclude, "/") {
		return strings.HasPrefix(filename, exclude) // prefix match required
	} else {
		return strings.HasPrefix(filename, exclude+"/") // prefix match plus / required
	}
}

// IsExcluded scans the exclude slices to find out whether f is excluded
func IsExcluded(program *ssa.Program, f *ssa.Function, exclude []string) bool {
	for _, e := range exclude {
		if isExcludedOne(program, f, e) {
			return true
		}
	}

	return false
}
