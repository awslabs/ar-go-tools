package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
	"go/parser"
	"go/token"
	"golang.org/x/tools/go/ssa"
	"log"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Match annotations of the form "@Source(id1, id2, id3)"
var SourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*\w\s*,?)+)\)`)
var SinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

type LPos struct {
	Filename string
	Line     int
}

func (p LPos) String() string {
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

func RemoveColumn(pos token.Position) LPos {
	return LPos{Line: pos.Line, Filename: pos.Filename}
}

// RelPos drops the column of the position and prepends reldir to the filename of the position
func RelPos(pos token.Position, reldir string) LPos {
	return LPos{Line: pos.Line, Filename: path.Join(reldir, pos.Filename)}
}

// getExpectedSourceToSink analyzes the files in dir and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from sources to sink in the form of a map from sink positions to all the source position that
// reach that sink.
func getExpectedSourceToSink(reldir string, dir string) map[LPos]map[LPos]bool {
	source2sink := map[LPos]map[LPos]bool{}
	sourceIds := map[string]token.Position{}
	fset := token.NewFileSet() // positions are relative to fset
	d, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
	if err != nil {
		fmt.Println(err)
		return source2sink
	}
	// Get all the source positions with their identifiers
	for _, f := range d {
		for _, f := range f.Files {
			for _, c := range f.Comments {
				for _, c1 := range c.List {
					pos := fset.Position(c1.Pos())
					// Match a "@Source(id1, id2, id3)"
					a := SourceRegex.FindStringSubmatch(c1.Text)
					if len(a) > 1 {
						for _, ident := range strings.Split(a[1], ",") {
							sourceIdent := strings.TrimSpace(ident)
							sourceIds[sourceIdent] = pos
						}
					}
				}
			}
		}
	}

	for _, f := range d {
		for _, f := range f.Files {
			for _, c := range f.Comments {
				for _, c1 := range c.List {
					sinkPos := fset.Position(c1.Pos())
					// Match a "@Sink(id1, id2, id3)"
					a := SinkRegex.FindStringSubmatch(c1.Text)
					if len(a) > 1 {
						for _, ident := range strings.Split(a[1], ",") {
							sourceIdent := strings.TrimSpace(ident)
							if sourcePos, ok := sourceIds[sourceIdent]; ok {
								relSink := RelPos(sinkPos, reldir)
								if _, ok := source2sink[relSink]; !ok {
									source2sink[relSink] = make(map[LPos]bool)
								}
								source2sink[relSink][RelPos(sourcePos, reldir)] = true
							}
						}
					}
				}
			}
		}
	}
	return source2sink
}

func checkExpectedPositions(t *testing.T, p *ssa.Program, flows dataflow.DataFlows, expect map[LPos]map[LPos]bool) {
	seen := make(map[LPos]map[LPos]bool)
	for sink, sources := range dataflow.ReachedSinkPositions(p, flows) {
		for source := range sources {
			posSink := RemoveColumn(sink)
			if _, ok := seen[posSink]; !ok {
				seen[posSink] = map[LPos]bool{}
			}
			posSource := RemoveColumn(source)
			if _, ok := expect[posSink]; ok && expect[posSink][posSource] {
				seen[posSink][posSource] = true
			} else {
				t.Errorf("ERROR in main.go: false positive: %s flows to %s\n", posSource, posSink)
			}
		}
	}

	for sinkLine, sources := range expect {
		for sourceLine := range sources {
			if !seen[sinkLine][sourceLine] {
				// Remaining entries have not been detected!
				t.Errorf("ERROR in main.go: failed to detect that %s flows to %s\n", sourceLine, sinkLine)
			}
		}
	}
}

// runTest runs a test instance by building the program from all the files in files plus a file "main.go", relative
// to the directory dirName
func runTest(t *testing.T, dirName string, files []string) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/cross-function/", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	// The LoadTest function is relative to the testdata/src/taint-tracking-inter folder so we can
	// load an entire module with subpackages
	program, cfg := utils.LoadTest(t, ".", files)

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := getExpectedSourceToSink(dir, ".")
	checkExpectedPositions(t, program, result.TaintFlows, expected)
}

func TestAll(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/cross-function/basic")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	sink2source := getExpectedSourceToSink(dir, ".")
	for sink, sources := range sink2source {
		for source := range sources {
			fmt.Printf("Source %s -> sink %s\n", source, sink)
		}
	}
}
