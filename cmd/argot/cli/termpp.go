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
	"io"

	"golang.org/x/term"
)

// Outputter provides a unified interface for writing output to either a terminal
// or standard writers. It automatically handles color formatting when writing to
// a terminal and falls back to plain text when writing to regular io.Writers.
//
// The Outputter can operate in two modes:
//   - Terminal mode: Uses a term.Terminal for colored output with escape sequences
//   - Writer mode: Uses separate io.Writers for normal output and error output
//
// This abstraction allows the same code to work in both interactive terminal
// environments and non-interactive contexts (like file output or pipes).
type Outputter struct {
	tt  *term.Terminal
	out io.Writer
	err io.Writer
}

// NewOutputter creates a new Outputter that writes to the provided io.Writers.
// This constructor is used for non-interactive environments where colored output
// is not desired or supported.
//
// Parameters:
//   - out: Writer for normal output messages
//   - err: Writer for error messages
//
// Returns an Outputter configured for plain text output without terminal features.
func NewOutputter(out io.Writer, err io.Writer) Outputter {
	return Outputter{out: out, err: err}
}

// NewTerminalOutputter creates a new Outputter that writes to a terminal.
// This constructor is used for interactive environments where colored output
// and terminal escape sequences are supported.
//
// Parameters:
//   - tt: Terminal instance that supports colored output and escape sequences
//
// Returns an Outputter configured for terminal output with color support.
func NewTerminalOutputter(tt *term.Terminal) Outputter {
	return Outputter{tt: tt}
}

// Writer returns the appropriate io.Writer for normal output.
// If the Outputter is configured with a terminal, it returns the terminal.
// Otherwise, it returns the configured output writer.
//
// This method provides access to the underlying writer for cases where
// direct writing is needed without formatting.
func (o Outputter) Writer() io.Writer {
	if o.tt != nil {
		return o.tt
	}
	return o.out
}

// WriteErr writes formatted error messages to the appropriate output channel.
// When using a terminal, the message is displayed in red color.
// When using writers, the message is written to the error writer.
//
// Parameters:
//   - format: Printf-style format string
//   - a: Arguments for the format string
//
// The message is automatically terminated with a newline when using terminal mode.
func (o Outputter) WriteErr(format string, a ...any) {
	if o.tt != nil {
		WriteErr(o.tt, format, a...)
	} else {
		fmt.Fprintf(o.err, format, a...)
	}
}

// WriteSuccess writes formatted success messages to the appropriate output channel.
// When using a terminal, the message is displayed in green color.
// When using writers, the message is written to the normal output writer.
//
// Parameters:
//   - format: Printf-style format string
//   - a: Arguments for the format string
//
// The message is automatically terminated with a newline when using terminal mode.
func (o Outputter) WriteSuccess(format string, a ...any) {
	if o.tt != nil {
		WriteSuccess(o.tt, format, a...)
	} else {
		fmt.Fprintf(o.out, format, a...)
	}
}

// Write writes formatted output to the appropriate output channel.
// This is the standard method for writing normal output messages.
// No special coloring is applied - use WriteErr or WriteSuccess for colored output.
//
// Parameters:
//   - format: Printf-style format string
//   - a: Arguments for the format string
//
// Unlike WriteErr and WriteSuccess, this method does not automatically add a newline.
func (o Outputter) Write(format string, a ...any) {
	if o.tt != nil {
		writeFmt(o.tt, format, a...)
	} else {
		fmt.Fprintf(o.out, format, a...)
	}
}

// EscBlue returns the ANSI escape sequence for blue text color.
// When using a terminal, returns the terminal's blue escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscBlue() []byte {
	if o.tt != nil {
		return o.tt.Escape.Blue
	}
	return []byte{}
}

// EscRed returns the ANSI escape sequence for red text color.
// When using a terminal, returns the terminal's red escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscRed() []byte {
	if o.tt != nil {
		return o.tt.Escape.Red
	}
	return []byte{}
}

// EscGreen returns the ANSI escape sequence for green text color.
// When using a terminal, returns the terminal's green escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscGreen() []byte {
	if o.tt != nil {
		return o.tt.Escape.Green
	}
	return []byte{}
}

// EscYellow returns the ANSI escape sequence for yellow text color.
// When using a terminal, returns the terminal's yellow escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscYellow() []byte {
	if o.tt != nil {
		return o.tt.Escape.Yellow
	}
	return []byte{}
}

// EscCyan returns the ANSI escape sequence for cyan text color.
// When using a terminal, returns the terminal's cyan escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscCyan() []byte {
	if o.tt != nil {
		return o.tt.Escape.Cyan
	}
	return []byte{}
}

// EscMagenta returns the ANSI escape sequence for magenta text color.
// When using a terminal, returns the terminal's magenta escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscMagenta() []byte {
	if o.tt != nil {
		return o.tt.Escape.Magenta
	}
	return []byte{}
}

// EscReset returns the ANSI escape sequence to reset text formatting.
// When using a terminal, returns the terminal's reset escape sequence.
// When using writers, returns an empty byte slice (no formatting reset needed).
//
// This method should be used after applying color escape sequences to return
// text formatting to normal.
func (o Outputter) EscReset() []byte {
	if o.tt != nil {
		return o.tt.Escape.Reset
	}
	return []byte{}
}

// EscWhite returns the ANSI escape sequence for white text color.
// When using a terminal, returns the terminal's white escape sequence.
// When using writers, returns an empty byte slice (no coloring).
//
// This method allows manual control over text coloring in terminal mode.
func (o Outputter) EscWhite() []byte {
	if o.tt != nil {
		return o.tt.Escape.White
	}
	return []byte{}
}

// WriteErr writes a formatted error message to the terminal in red color.
// The message is automatically terminated with a newline and the color
// formatting is reset after the message.
//
// Parameters:
//   - tt: Terminal to write to
//   - format: Printf-style format string
//   - a: Arguments for the format string
//
// This is a convenience function for writing error messages with consistent
// red coloring in terminal environments.
func WriteErr(tt *term.Terminal, format string, a ...any) {
	writelnEscape(tt, tt.Escape.Red, format, a...)
}

// WriteSuccess writes a formatted success message to the terminal in green color.
// The message is automatically terminated with a newline and the color
// formatting is reset after the message.
//
// Parameters:
//   - tt: Terminal to write to
//   - format: Printf-style format string
//   - a: Arguments for the format string
//
// This is a convenience function for writing success messages with consistent
// green coloring in terminal environments.
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

func writeEntries(o Outputter, sess *Session, entries []displayElement, prefix string) {
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
	cols := sess.termWidth / maxLen
	if cols <= 0 {
		cols = 1
	}
	lines := len(entries)/cols + 1
	for line := 0; line < lines; line++ {
		o.Write("%s", prefix)
		for col := 0; col < cols; col++ {
			index := col*lines + line
			if index < len(entries) {
				o.Write("%s%-*s%s", entries[index].escape, maxLen, entries[index].content, o.EscReset())
			}
		}
		o.Write("\n")
	}
}
