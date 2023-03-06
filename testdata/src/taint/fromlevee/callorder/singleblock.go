package callorder

// This set of tests is borrowed from go-flow-levee
// https://github.com/google/go-flow-levee/blob/master/internal/pkg/levee/testdata/src/levee_analysistest/example/tests/callorder/singleblock.go

import (
	"fmt"
	"fromlevee/core"
	"io"
	"os"
)

func TestTaintBeforeSinking(w io.Writer) {
	s := core.Source() // @Source(sb1)
	_, _ = fmt.Fprintf(w, "%v", s)
	core.Sink(w) // @Sink(sb1)
}

func TestSinkBeforeTainting(w io.Writer) {
	s := core.Source()
	core.Sink(w)
	_, _ = fmt.Fprintf(w, "%v", s)
}

func TestSinkBeforeAndAfterTainting(w io.Writer) {
	s := core.Source() // @Source(sb2)
	core.Sink(w)
	_, _ = fmt.Fprintf(w, "%v", s)
	core.Sink(w) // @Sink(sb2)
}

func TestAllSingleBlock() {
	TestTaintBeforeSinking(os.Stdout)
	TestSinkBeforeTainting(os.Stdout)
	TestSinkBeforeAndAfterTainting(os.Stdout)
}
