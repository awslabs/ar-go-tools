package main

import (
	"fmt"

	"golang.org/x/term"
)

// WriteErr formats format with a and then prints on the terminal in red with a new line
func WriteErr(tt *term.Terminal, format string, a ...any) {
	writelnEscape(tt, tt.Escape.Red, format, a...)
}

// WriteSuccess formats format with a and then prints on the terminal in green with a new line
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
