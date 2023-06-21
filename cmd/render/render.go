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

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/render"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// edgeColor defines specific color for specific edges in the callgraph
// - a go call site will be colored with a blue edge
// - all other call sites will have a default color edge
func edgeColor(edge *callgraph.Edge) string {
	_, isGo := edge.Site.(*ssa.Go)
	if isGo {
		return "[color=blue]"
	}
	return ""
}

func nodeStr(node *callgraph.Node) string {
	return node.Func.String()
}

func pkgString(node *callgraph.Node) string {
	if node != nil && node.Func != nil {
		if node.Func.Pkg != nil {
			return node.Func.Pkg.String()
		}
	}
	return ""
}

func fnName(node *callgraph.Node) string {
	if node != nil && node.Func != nil {
		return node.Func.Name()
	} else {
		return ""
	}
}

var ExcludedNodes = []string{"String", "GoString", "init", "Error", "Code", "Message", "Err", "OrigErr"}

func filterFn(edge *callgraph.Edge) bool {
	for _, name := range ExcludedNodes {
		if fnName(edge.Callee) == name || fnName(edge.Caller) == name {
			return false
		}
	}
	return true
}

// WriteCrossFunctionGraph writes a graphviz representation of the cross-function dataflow graph to w.
func WriteCrossFunctionGraph(cfg *config.Config, logger *config.LogGroup, program *ssa.Program, w io.Writer) error {
	// every function should be included in the graph
	// building the graph doesn't require souce/sink logic
	state, err := dataflow.NewInitializedAnalyzerState(logger, cfg, program)
	if err != nil {
		return fmt.Errorf("failed to build analyzer state: %w", err)
	}

	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		AnalyzerState:       state,
		NumRoutines:         numRoutines,
		ShouldCreateSummary: dataflow.ShouldCreateSummary,
		ShouldBuildSummary:  dataflow.ShouldBuildSummary,
		IsEntrypoint:        func(*config.Config, ssa.Node) bool { return true },
	})

	state, err = render.BuildCrossFunctionGraph(state)
	if err != nil {
		return fmt.Errorf("failed to build cross-function graph: %w", err)
	}

	state.FlowGraph.Print(w)

	return nil
}

// WriteGraphviz writes a graphviz representation the call-graph to w
func WriteGraphviz(config *config.Config, cg *callgraph.Graph, w io.Writer) error {
	var err error
	before := "digraph callgraph {\n"
	after := "}\n"

	_, err = w.Write([]byte(before))
	if err != nil {
		return fmt.Errorf("error while writing in file: %w", err)
	}
	if err := callgraph.GraphVisitEdges(cg, func(edge *callgraph.Edge) error {
		if edge.Caller.Func != nil && edge.Callee.Func != nil &&
			strings.HasPrefix(pkgString(edge.Caller), "package "+config.PkgFilter) &&
			strings.HasPrefix(pkgString(edge.Callee), "package "+config.PkgFilter) &&
			filterFn(edge) {
			s := fmt.Sprintf("  \"%s\" -> \"%s\" %s;\n",
				nodeStr(edge.Caller), nodeStr(edge.Callee), edgeColor(edge))
			_, err := w.Write([]byte(s))
			if err != nil {
				return fmt.Errorf("error while writing in file: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	_, err = w.Write([]byte(after))
	if err != nil {
		return fmt.Errorf("error while writing in file: %w", err)
	}
	return nil
}

func GraphvizToFile(config *config.Config, cg *callgraph.Graph, filename string) error {
	var err error
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	err = WriteGraphviz(config, cg, w)
	if err != nil {
		return fmt.Errorf("error while writing graph: %w", err)
	}
	return err
}

// OutputSsaPackages writes the ssa representation of a program p.
// Each package is written in its own folder.
// This function may panic.
func OutputSsaPackages(p *ssa.Program, dirName string) error {
	allPackages := p.AllPackages()
	if len(allPackages) <= 0 {
		fmt.Print("No package found.")
		return nil
	}
	err := os.MkdirAll(dirName, 0700)
	if err != nil {
		return fmt.Errorf("could not create directory %s: %v", dirName, err)
	}
	for _, pkg := range allPackages {
		// Make a directory corresponding to the package path minus last elt
		appendDirPath, _ := filepath.Split(pkg.Pkg.Path())
		fullDirPath := dirName
		if appendDirPath != "" {
			// Only create new directory if necessary
			fullDirPath = filepath.Join(fullDirPath, appendDirPath)
			err := os.MkdirAll(fullDirPath, 0700)
			if err != nil {
				return fmt.Errorf("could not create directory %s: %v", dirName, err)
			}
		}
		filename := pkg.Pkg.Name() + ".ssa"
		ssaFilePath := filepath.Join(fullDirPath, filename)

		packageToFile(p, pkg, ssaFilePath)
	}
	return nil
}

func writeAnons(b bytes.Buffer, f *ssa.Function) {
	for _, anon := range f.AnonFuncs {
		ssa.WriteFunction(&b, anon)
		writeAnons(b, anon)
	}
}

func packageToFile(p *ssa.Program, pkg *ssa.Package, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	var b bytes.Buffer

	// Write the package summary
	ssa.WritePackage(&b, pkg)
	// Write all the functions and members in buffer
	for _, pkgMember := range pkg.Members {
		switch pkgM := pkgMember.(type) {
		case *ssa.Function:
			ssa.WriteFunction(&b, pkgM)
			writeAnons(b, pkgM)
			b.WriteTo(w)
			b.Reset()
		case *ssa.Global:
			fmt.Fprintf(w, "%s\n", pkgM.String())
		case *ssa.Type:
			methods := typeutil.IntuitiveMethodSet(pkgM.Type(), &p.MethodSets)
			for _, sel := range methods {
				functionMethod := p.MethodValue(sel)
				if functionMethod != nil {
					ssa.WriteFunction(&b, functionMethod)
					b.WriteTo(w)
					b.Reset()
				}
			}
		}
	}
}

func WriteHtmlCallgraph(program *ssa.Program, cg *callgraph.Graph, outPath string) error {
	// fmt.Fprint(os.Stderr, "Starting writeCallgraph\n")
	reachable := dataflow.CallGraphReachable(cg, false, false)
	htmlOut, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer htmlOut.Close()
	htmlOut.WriteString(`
	<style>
	.func {
		margin: 0 0 0.5em;
		border: 1px solid #BBB;
		padding: 8px;
	  }
	  :target {
		background: #FFE;
	  }
	  .name {
		font-weight: bold;
	  }
	  .fullname {
		color: #999;
	  }
	  </style>
	  ` + "\n")
	for fun := range reachable {
		if fun == nil {
			continue
		}
		node := cg.Nodes[fun]
		includeDisassembly := false
		fmt.Fprint(htmlOut, "<div class=func id=\"", uintptr(unsafe.Pointer(fun)), "\">func <span class=name>",
			fun.Name(), "</span>()\n")
		fmt.Fprint(htmlOut, "<div class=fullname>", fun.String(), "</div>\n")
		for _, bb := range fun.Blocks {
			for _, ins := range bb.Instrs {
				switch call := ins.(type) {
				case *ssa.Call:
					fmt.Fprintf(htmlOut, "<div>Call at %v </div>\n", program.Fset.Position(ins.Pos()))
					if _, ok := call.Call.Value.(*ssa.Builtin); ok {
						// Built-ins are not part of the explicit callgraph
						fmt.Fprintf(htmlOut, "(Builtin)\n")
						// fmt.Fprintf(html, "CalleeCount at %v: %v\n", program.Fset.Position(ins.Pos()), 1)
					} else {
						callees := []*ssa.Function{}
						for _, edge := range node.Out {
							if edge.Site == ins {
								callees = append(callees, edge.Callee.Func)
							}
						}
						// fmt.Fprintf(html, "CalleeCount at %v: %v\n", program.Fset.Position(ins.Pos()), len(callees))
						if len(callees) == 0 && call.Call.StaticCallee() != nil {
							fmt.Fprintf(htmlOut, "(Predefined)\n")
						} else if len(callees) == 0 {
							fmt.Fprintf(htmlOut, "No callees at %v\n", program.Fset.Position(ins.Pos()))
							includeDisassembly = true
						} else {
							for _, c := range callees {
								fmt.Fprint(htmlOut, "<a href=\"#", uintptr(unsafe.Pointer(c)), "\", title=\"",
									c.String(), "\">", c.Name(), "</a> ")
							}
						}
					}

					// fmt.Fprintf(html, "</div>\n")
				}
			}
		}
		fmt.Fprint(htmlOut, "<div>Callers:</div>\n")
		for _, edge := range node.In {
			f := edge.Caller.Func
			isDead := ""
			if _, ok := reachable[f]; !ok {
				isDead = "(Dead)"
			}
			fmt.Fprint(htmlOut, "<div>", isDead, "<a href=\"#", uintptr(unsafe.Pointer(f)), "\">",
				f.Name(), "</a> <span class=fullname>", f.String(), " </span></div>")
		}
		if includeDisassembly {
			if syn := fun.Syntax(); syn != nil {
				fmt.Fprint(htmlOut, "<details><summary>Source</summary><pre>\n")
				file := program.Fset.File(syn.Pos())
				if file != nil {
					reader, _ := os.Open(file.Name())
					b := make([]byte, syn.End()-syn.Pos())
					reader.ReadAt(b, int64(file.Offset(syn.Pos())))
					fmt.Fprint(htmlOut, html.EscapeString(strings.ReplaceAll(string(b), "\t", "    ")))

				} else {
					fmt.Fprint(htmlOut, "No file source found")
				}
				fmt.Fprint(htmlOut, "</pre></details>\n")
			}

			fmt.Fprint(htmlOut, "<details><summary>Assembly</summary><pre>\n")
			buffer := bytes.NewBufferString("")
			ssa.WriteFunction(buffer, fun)
			fmt.Fprint(htmlOut, html.EscapeString(buffer.String()))
			fmt.Fprint(htmlOut, "</pre></details>\n")
		}
		fmt.Fprint(htmlOut, "</div>\n")
	}
	return nil
}
