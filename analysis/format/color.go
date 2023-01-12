// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package format

import (
	"fmt"

	"golang.org/x/term"
)

var (
	Faint  = Color("\033[2m%s\033[0m")
	Red    = Color("\033[1;31m%s\033[0m")
	Green  = Color("\033[1;32m%s\033[0m")
	Yellow = Color("\033[1;33m%s\033[0m")
	Purple = Color("\033[1;34m%s\033[0m")
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
