package main

import (
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
)

func AutoCompleteOfCache(_ *dataflow.Cache) func(string, int, rune) (string, int, bool) {
	f := func(line string, pos int, key rune) (string, int, bool) {
		if key == '\t' {
			if len(line) > 1 && pos == len(line) {
				pc := 0
				compl := line
				for cmd := range commands {
					if strings.HasPrefix(cmd, line) {
						pc++
						compl = cmd
					}
				}
				if pc == 1 {
					return compl, len(compl), true
				}
			}
		}
		return "", 0, false
	}
	return f
}
