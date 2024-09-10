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

package compare

import (
	"bufio"
	"os"
	"strings"
)

// readNMFile reads a file produced from the executable binary using
// go tool nm > filename
// todo: figure out how to execute nm directly and scarf the stdout
// todo: link https://pkg.go.dev/cmd/internal/objfile@go1.19.3 and
// process the symbol structs directly
func readNMFile(filename string) (map[string]bool, error) {
	symbols := make(map[string]bool)
	infile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	fileScanner := bufio.NewScanner(infile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		entry := strings.Split(fileScanner.Text(), " ")
		if len(entry) != 4 || entry[2] != "T" {
			//fmt.Fprintln(os.Stderr, len(entry), entry)
			continue
		}

		name := entry[3]
		// if the name contains an embedded (*, move it to the start of the string
		// to match the name formatting used by the ssa package.
		index := strings.Index(name, "(*")
		if index > 0 {
			name = "(*" + name[:index] + name[index+2:]
		}

		if strings.HasPrefix(name, "type..eq.") || strings.HasPrefix(name, "type..hash.") {
			continue
		}

		if strings.HasSuffix(name, ".abi0") {
			name = name[:len(name)-5]
		}

		n := strings.LastIndex(name, ".func")
		if n != -1 {
			name = name[:n] + "$" + name[n+5:]
		}

		symbols[name] = true
	}

	infile.Close()

	return symbols, nil
}
