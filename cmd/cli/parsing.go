package main

import (
	"strings"

	"github.com/google/shlex"
)

// Command contains the parsed arguments and name of a command in the command-line tool
type Command struct {
	// Name is the name of the command (e.g. exit, ls, ...)
	Name string

	// Args contains all the non-named arguments (arguments without keys)
	Args []string

	// NamedArgs contains all the named arguments (arguments --key value)
	NamedArgs map[string]string

	// Flags contains all the flags (arguments -key)
	Flags map[string]bool
}

// ParseCommand parses a command of the form "command arg1 arg2 -name1 namedArg1 -flag1 arg3"
//   - the first string is the name of the command
//   - every string preceded by -- is a named argument, and the next string will be parsed as its value
//     A valid named argument MUST have a value.
//   - every string preceded by - but not -- is a flag,
//   - every other string will be a non named argument
func ParseCommand(cmd string) Command {
	command := Command{
		Name:      "",
		Args:      nil,
		NamedArgs: map[string]string{},
		Flags:     map[string]bool{},
	}

	tokens, err := shlex.Split(cmd)
	if err != nil {
		return command
	}

	flagCmdName := false
	flagArgName := false
	argName := ""

	for _, token := range tokens {
		if !flagCmdName {
			command.Name = token
			flagCmdName = true // set, will not be reset
		} else if name, foundNamed := strings.CutPrefix(token, "--"); foundNamed && !flagArgName {
			// argument with prefix -- is for named argument with value
			argName = name
			flagArgName = true // set

		} else if flag, foundFlag := strings.CutPrefix(token, "-"); foundFlag {
			// argument with prefix - (and not --) is for flag without value
			command.Flags[flag] = true
		} else if flagArgName {
			command.NamedArgs[argName] = token
			flagArgName = false // reset
		} else {
			command.Args = append(command.Args, token)
		}
	}

	return command
}
