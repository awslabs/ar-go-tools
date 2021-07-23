// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// conversion of Go identifiers into C/C++ identifiers
package main

import (
	"golang.org/x/tools/go/ssa"
	"strings"
)

func convertIdentifier(f *ssa.Function) string {

	fullName := f.RelString(nil)

	var result strings.Builder

	for _, c := range fullName {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result.WriteRune(c)
		} else {
			result.WriteRune('_')
		}
	}

	return result.String()
}
