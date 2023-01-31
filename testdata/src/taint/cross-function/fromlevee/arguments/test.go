// This set of tests is borrowed from go-flow-levee

package arguments

import (
	"fromlevee/core"
)

func TestSourceFromParamByReference(s *core.Container) {
	core.Sink("Source in the parameter %v", s) // @Sink(arg)
}

func TestSourceMethodFromParamByReference(s *core.Container) {
	core.Sink("Source in the parameter %v", s.Data) // @Sink(arg)
}

func TestSourceFromParamByReferenceInfo(s *core.Container) {
	core.Sink(s) // @Sink(arg)
}

func TestSourceFromParamByValue(s core.Container) {
	core.Sink("Source in the parameter %v", s) // @Sink(arg)
}

func TestUpdatedSource(s *core.Container) {
	s.Data = "updated"
	core.Sink("Updated %v", s) // @Sink(arg)
}

func TestSourceFromAPointerCopy(s *core.Container) {
	cp := s
	core.Sink("Pointer copy of the source %v", cp) // @Sink(arg)
}

func TestAll() {
	s := core.Source3() // @Source(arg)
	TestSourceFromAPointerCopy(&s)
	TestSourceFromParamByReference(&s)
	TestSourceMethodFromParamByReference(&s)
	TestSourceFromParamByReferenceInfo(&s)
	TestSourceFromParamByValue(s)
	TestUpdatedSource(&s)
}
