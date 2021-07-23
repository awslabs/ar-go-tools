// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"golang.org/x/tools/go/ssa"
	"os"
	"strings"
)

func makeAbsolute(excludeRelative []string) []string {
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

func isExcluded(program *ssa.Program, f *ssa.Function, exclude []string) bool {
	for _, e := range exclude {
		if isExcludedOne(program, f, e) {
			return true
		}
	}

	return false
}
