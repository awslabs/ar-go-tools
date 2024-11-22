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
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
)

// AutoCompleteOfAnalyzerState provides the auto-completion functionality for the command-line interface
func AutoCompleteOfAnalyzerState(_ *dataflow.State) func(string, int, rune) (string, int, bool) {
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
