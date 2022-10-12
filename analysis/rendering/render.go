package render

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
	"io"
	"os"
	"path/filepath"
)

// WriteGraphviz writes a graphviz representation the call-graph to w
func WriteGraphviz(cg *callgraph.Graph, w io.Writer) error {
	var err error
	before := "digraph callgraph {\n"
	after := "}\n"

	_, err = w.Write([]byte(before))
	if err != nil {
		return fmt.Errorf("error while writing in file: %w", err)
	}
	if err := callgraph.GraphVisitEdges(cg, func(edge *callgraph.Edge) error {
		s := fmt.Sprintf("  \"%s\" -> \"%s\"\n", edge.Caller.String(), edge.Callee.String())
		_, err := w.Write([]byte(s))
		if err != nil {
			return fmt.Errorf("error while writing in file: %w", err)
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

func GraphvizToFile(cg *callgraph.Graph, filename string) error {
	var err error
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	err = WriteGraphviz(cg, w)
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

func packageToFile(p *ssa.Program, pkg *ssa.Package, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	var b bytes.Buffer
	defer b.WriteTo(w)

	// Write the package summary
	ssa.WritePackage(&b, pkg)
	// Write all the functions and members in buffer
	for _, pkgMember := range pkg.Members {
		switch pkgM := pkgMember.(type) {
		case *ssa.Function:
			ssa.WriteFunction(&b, pkgM)
		case *ssa.Type:
			methods := typeutil.IntuitiveMethodSet(pkgM.Type(), &p.MethodSets)
			for _, sel := range methods {
				functionMethod := p.MethodValue(sel)
				if functionMethod != nil {
					ssa.WriteFunction(&b, functionMethod)
				}
			}
		}
	}
}
