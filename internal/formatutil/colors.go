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
	// Bold formats the arguments in bold for terminals
	Bold = Color("\033[1m%s\033[0m")
	// Underline formats the arguments in underline for terminals
	Underline = Color("\033[4m%s\033[0m")
	// Faint format the arguments in faint for terminals
	Faint = Color("\033[2m%s\033[0m")
	// Italic formats the arguments in italic for terminals
	Italic = Color("\033[3m%s\033[0m")
	// Red formats the arguments in red for terminals
	Red = Color("\033[1;31m%s\033[0m")
	// Green formats the arguments in green for terminals
	Green = Color("\033[1;32m%s\033[0m")
	// Yellow formats the arguments in yellow for terminals
	Yellow = Color("\033[1;33m%s\033[0m")
	// Blue formats the arguments in blue for terminals
	Blue = Color("\033[1;34m%s\033[0m")
	// Magenta formats the arguments in magenta for terminals
	Magenta = Color("\033[1;35m%s\033[0m")
	// Cyan formats the arguments in cyan for terminals
	Cyan = Color("\033[1;36m%s\033[0m")
	// White formats the arguments in white for terminals
	White = Color("\033[1;37m%s\033[0m")
	// Black formats the arguments in black for terminals
	Black = Color("\033[1;30m%s\033[0m")
	// Gray formats the arguments in gray for terminals
	Gray = Color("\033[1;90m%s\033[0m")
	// BrightRed formats the arguments in bright red for terminals
	BrightRed = Color("\033[1;91m%s\033[0m")
	// BrightGreen formats the arguments in bright green for terminals
	BrightGreen = Color("\033[1;92m%s\033[0m")
	// BrightYellow formats the arguments in bright yellow for terminals
	BrightYellow = Color("\033[1;93m%s\033[0m")
	// BrightBlue formats the arguments in bright blue for terminals
	BrightBlue = Color("\033[1;94m%s\033[0m")
	// BrightMagenta formats the arguments in bright magenta for terminals
	BrightMagenta = Color("\033[1;95m%s\033[0m")
	// BrightCyan formats the arguments in bright cyan for terminals
	BrightCyan = Color("\033[1;96m%s\033[0m")
	// BrightWhite formats the arguments in bright white for terminals
	BrightWhite = Color("\033[1;97m%s\033[0m")
	// BgRed formats the arguments in red background for terminals
	BgRed = Color("\033[1;41m%s\033[0m")
	// BgGreen formats the arguments in green background for terminals
	BgGreen = Color("\033[1;42m%s\033[0m")
	// BgOrange formats the arguments in orange background for terminals
	BgOrange = Color("\033[1;43m%s\033[0m")
	// BgBlue formats the arguments in blue background for terminals
	BgBlue = Color("\033[1;44m%s\033[0m")
	// BgMagenta formats the arguments in magenta background for terminals
	BgMagenta = Color("\033[1;45m%s\033[0m")
	// BgCyan formats the arguments in cyan background for terminals
	BgCyan = Color("\033[1;46m%s\033[0m")
	// BgWhite formats the arguments in white background for terminals
	BgWhite = Color("\033[1;47m%s\033[0m")
	// BgDarkGray formats the arguments in dark gray background for terminals
	BgDarkGray = Color("\033[1;100m%s\033[0m")
	// BgLightRed formats the arguments in light red background for terminals
	BgLightRed = Color("\033[1;101m%s\033[0m")
	// BgLightGreen formats the arguments in light green background for terminals
	BgLightGreen = Color("\033[1;102m%s\033[0m")
	// BgYellow formats the arguments in yellow background for terminals
	BgYellow = Color("\033[1;103m%s\033[0m")
	// BgLightBlue formats the arguments in light blue background for terminals
	BgLightBlue = Color("\033[1;104m%s\033[0m")
	// BgLightPurple formats the arguments in light purple background for terminals
	BgLightPurple = Color("\033[1;105m%s\033[0m")
)

// Color is a formatter helper that wraps the arguments suing the color string provided.
// Checks whether the standard output is a terminal.
func Color(colorString string) func(...interface{}) string {
	result := func(args ...interface{}) string {
		if term.IsTerminal(1) {
			return fmt.Sprintf(colorString,
				fmt.Sprint(args...))
		}
		return fmt.Sprint(args...)
	}
	return result
}

// Sanitize is a simple sanitizer that removes all escape sequences
func Sanitize(s string) string {
	r := fmt.Sprintf("%q", s)
	if len(r) >= 2 {
		return r[1 : len(r)-1]
	}
	return r
}

// SanitizeRepr is a simple sanitizer that removes all escape sequences from the string representation of an object
func SanitizeRepr(s fmt.Stringer) string {
	return Sanitize(s.String())
}
