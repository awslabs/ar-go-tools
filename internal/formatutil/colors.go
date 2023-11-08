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

// Package formatutil manipulates string colors and other formatting operations.
package formatutil

import (
	"fmt"

	"golang.org/x/term"
)

var (
	Bold    = Color("\033[1m%s\033[0m")
	Faint   = Color("\033[2m%s\033[0m")
	Italic  = Color("\033[3m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Green   = Color("\033[1;32m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Cyan    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

func Color(colorString string) func(...interface{}) string {
	result := func(args ...interface{}) string {
		if term.IsTerminal(1) {
			return fmt.Sprintf(colorString,
				fmt.Sprint(args...))
		} else {
			return fmt.Sprint(args...)
		}
	}
	return result
}

// Sanitize is a simple sanitizer that removes all escape sequences
func Sanitize(s string) string {
	r := fmt.Sprintf("%q", s)
	if len(r) >= 2 {
		return r[1 : len(r)-1]
	} else {
		return r
	}
}

// SanitizeRepr is a simple sanitizer that removes all escape sequences from the string representation of an object
func SanitizeRepr(s fmt.Stringer) string {
	return Sanitize(s.String())
}
