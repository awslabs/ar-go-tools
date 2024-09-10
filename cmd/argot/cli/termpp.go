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

package cli

import (
	"fmt"

	"golang.org/x/term"
)

// WriteErr formats the format string with a and then prints on the terminal in red with a new line
func WriteErr(tt *term.Terminal, format string, a ...any) {
	writelnEscape(tt, tt.Escape.Red, format, a...)
}

// WriteSuccess formats the format string with a and then prints on the terminal in green with a new line
func WriteSuccess(tt *term.Terminal, format string, a ...any) {
	writelnEscape(tt, tt.Escape.Green, format, a...)
}

func writeFmt(tt *term.Terminal, format string, a ...any) {
	var s string
	if len(a) > 0 {
		s = fmt.Sprintf(format, a...)
	} else {
		s = format
	}
	tt.Write([]byte(s))
}

func writelnEscape(tt *term.Terminal, escape []byte, format string, a ...any) {
	tt.Write(escape)
	writeFmt(tt, format, a...)
	tt.Write(tt.Escape.Reset)
	tt.Write([]byte("\n"))
}

type displayElement struct {
	content string
	escape  []byte
}

func writeEntries(tt *term.Terminal, entries []displayElement, prefix string) {
	if len(entries) == 0 {
		return
	}
	maxLen := 0
	for _, entry := range entries {
		if len(entry.content) > maxLen {
			maxLen = len(entry.content)
		}
	}

	maxLen = maxLen + 3 // padding
	cols := state.TermWidth / maxLen
	if cols <= 0 {
		cols = 1
	}
	lines := len(entries)/cols + 1
	for line := 0; line < lines; line++ {
		writeFmt(tt, prefix)
		for col := 0; col < cols; col++ {
			index := col*lines + line
			if index < len(entries) {
				writeFmt(tt, "%s%-*s%s", entries[index].escape, maxLen, entries[index].content, tt.Escape.Reset)
			}
		}
		writeFmt(tt, "\n")
	}
}
