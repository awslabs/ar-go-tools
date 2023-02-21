package render

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
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
			strings.HasPrefix(pkgString(edge.Caller), "package "+config.PkgPrefix) &&
			strings.HasPrefix(pkgString(edge.Callee), "package "+config.PkgPrefix) &&
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
