package main

import (
	"strings"

	"github.com/google/shlex"
)

// Command contains the parsed arguments and name of a command in the command-line tool
type Command struct {
	// Name is the name of the command (e.g. exit, ls, ...)
	Name string

	// Args contains all the non-named arguments
	Args []string

	// NamedArgs contains all the named arguments.
	NamedArgs map[string]string
}

// ParseCommand parses a command of the form "command arg1 arg1 -name1 namedArg1"
//   - the first string is the name of the command
//   - every string preceded by - is a named argument, and the next string will be parsed as its value
//     A valid named argument MUST have a value.
//   - every other string will be a non named argument
func ParseCommand(cmd string) Command {
	command := Command{
		Name:      "",
		Args:      nil,
		NamedArgs: map[string]string{},
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
		} else if name, found := strings.CutPrefix(token, "-"); found && !flagArgName {
			argName = name
			flagArgName = true // set

		} else if flagArgName {
			command.NamedArgs[argName] = token
			flagArgName = false // reset
		} else {
			command.Args = append(command.Args, token)
		}
	}

	return command
}
