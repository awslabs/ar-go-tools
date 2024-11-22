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
	"go/ast"
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

func cmdScan(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : scan the program for usages\n", tt.Escape.Blue, cmdScanName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "Please specify which usages to scan.")
		return false
	}
	// otherwise build regex from arguments
	var x []string
	for _, arg := range command.Args {
		x = append(x, "("+arg+")")
	}

	rString := strings.Join(x, "|")
	target, err := regexp.Compile(rString)
	if err != nil {
		regexErr(tt, rString, err)
		return false
	}

	for _, pack := range state.InitialPackages {
		scanUsages(tt, pack, target)
	}

	return false
}

func scanUsages(tt *term.Terminal, p *packages.Package, target *regexp.Regexp) {
	for _, astFile := range p.Syntax {
		ast.Inspect(astFile,
			func(n ast.Node) bool {
				switch node := n.(type) {
				case ast.Expr:
					typ := p.TypesInfo.TypeOf(node)
					if typ != nil && target.MatchString(typ.String()) {
						writeFmt(tt, "- of type %s: %s\n", typ.String(), p.Fset.Position(node.Pos()))
						desc := astutil.NodeDescription(node)
						writeFmt(tt, "   %s\n", desc)
					}

					return true
				case *ast.Ident:
					if target.MatchString(node.Name) {
						ks := "unknown"
						if node.Obj != nil {
							ks = ast.ObjKind.String(node.Obj.Kind)
						}
						writeFmt(tt, "- ident %s [%s]: %s\n", node.String(), ks, p.Fset.Position(node.Pos()))
					}
					return false

				default:
					return true
				}
			})
	}
}
