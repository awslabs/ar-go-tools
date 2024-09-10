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
	"github.com/awslabs/ar-go-tools/internal/shims"
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
		} else if name, foundNamed := shims.CutPrefix(token, "--"); foundNamed && !flagArgName {
			// argument with prefix -- is for named argument with value
			argName = name
			flagArgName = true // set

		} else if flag, foundFlag := shims.CutPrefix(token, "-"); foundFlag {
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
