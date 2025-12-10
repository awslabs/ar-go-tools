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

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

func cmdScan(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : scan the program for usages\n", o.EscBlue(), CmdScanName, o.EscReset())
		return false
	}

	if len(command.Args) == 0 {
		o.WriteErr("Please specify which usages to scan.")
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
		regexErr(o, rString, err)
		return false
	}

	// Get the program
	lp := sess.loadProgram(o)
	if lp.IsErr() {
		o.WriteErr("Unable to load program: %s", lp)
		return false
	}

	for _, pack := range lp.Unwrap().Packages {
		scanUsages(o, pack, target)
	}

	return false
}

func scanUsages(o Outputter, p *packages.Package, target *regexp.Regexp) {
	for _, astFile := range p.Syntax {
		ast.Inspect(astFile,
			func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					if target.MatchString(node.Name) {
						ks := "unknown"
						if node.Obj != nil {
							ks = ast.ObjKind.String(node.Obj.Kind)
						}
						o.Write("- ident %s [%s]: %s\n", node.String(), ks, p.Fset.Position(node.Pos()))
					}
					return false
				case ast.Expr:
					typ := p.TypesInfo.TypeOf(node)
					if typ != nil && target.MatchString(typ.String()) {
						o.Write("- of type %s: %s\n", typ.String(), p.Fset.Position(node.Pos()))
						desc := astutil.NodeDescription(node)
						o.Write("   %s\n", desc)
					}

					return true
				default:
					return true
				}
			})
	}
}
