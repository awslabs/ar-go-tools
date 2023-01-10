package taint

import (
	"fmt"
	"go/parser"
	"go/token"
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

type PosNoColumn struct {
	Filename string
	Line     int
}

func (p PosNoColumn) String() string {
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

func RemoveColumn(pos token.Position) PosNoColumn {
	return PosNoColumn{Line: pos.Line, Filename: pos.Filename}
}

// RelPos drops the column of the position and prepends reldir to the filename of the position
func RelPos(pos token.Position, reldir string) PosNoColumn {
	return PosNoColumn{Line: pos.Line, Filename: path.Join(reldir, pos.Filename)}
}

func getExpectedSourceToSink(reldir string, dir string) map[PosNoColumn]map[PosNoColumn]bool {
	source2sink := map[PosNoColumn]map[PosNoColumn]bool{}
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
									source2sink[relSink] = make(map[PosNoColumn]bool)
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
