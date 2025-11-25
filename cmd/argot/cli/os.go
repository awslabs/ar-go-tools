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
	"os"
	"path"
)

// cmdCd implements the "cd" command that lets the user change the current working directory in the tool
func cmdCd(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : move to relative directory\n", o.EscBlue(), CmdCdName, o.EscReset())
		return false
	}
	if len(command.Args) == 1 {
		wd, err := os.Getwd()
		if err != nil {
			o.WriteErr("Could not get working directory: %s. Abort.", err)
			return false
		}
		dirName := path.Join(wd, command.Args[0])
		if err := os.Chdir(dirName); err != nil {
			o.WriteErr("Could not change directory: %s", err)
			return false
		}
	} else {
		o.WriteErr("cd expects exactly one argument")
	}
	return false
}

// cmdExit implements the exit command to exit the command-line tool.
func cmdExit(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : exit the program\n", o.EscBlue(), CmdExitName, o.EscReset())
		return false
	}
	o.Write("%sExiting...%s\n", o.EscMagenta(), o.EscReset())
	return true
}

// cmdLs prints the entries in the current directory. Useful to navigate the current directory and load a new program
// or a new configuration file.
func cmdLs(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : list files in directory\n", o.EscBlue(), CmdLsName, o.EscReset())
		return false
	}
	var extraPath string
	if len(command.Args) > 0 {
		extraPath = command.Args[0]
	}
	wd, _ := os.Getwd()
	entries, err := os.ReadDir(path.Join(wd, extraPath))
	if err != nil {
		o.WriteErr("error listing directory %s: %s", wd, err)
		return false
	}
	var strEntries []displayElement
	for _, entry := range entries {
		if entry.IsDir() {
			strEntries = append(strEntries,
				displayElement{escape: o.EscCyan(), content: entry.Name()})
		} else {
			strEntries = append(strEntries,
				displayElement{content: entry.Name(), escape: o.EscReset()})
		}
	}
	writeEntries(o, sess, strEntries, "")
	return false
}
