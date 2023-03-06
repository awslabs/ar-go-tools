package embedding

import (
	"fromlevee/core"
)

type EmbedsSource struct {
	core.Container
}

type EmbedsSourcePointer struct {
	*core.Container
}

func TestStructThatEmbedsSourceIsSource() {
	core.Sink(EmbedsSource{core.Source3()}) // @Source(em1) @Sink(em1)
}

func TestStructThatEmbedsSourcePointerIsSource() {
	s := core.Source3()                // @Source(em2)
	core.Sink(EmbedsSourcePointer{&s}) //  @Sink(em2)
}

func TestEmbeddedSourceIsSource() {
	s := core.Source3()             // @Source(em3)
	core.Sink(EmbedsSource{s}.Data) // @Sink(em3)
}

func TestEmbeddedSourcePointerIsSource() {
	s := core.Source3()                     //  @Source(em4)
	core.Sink(EmbedsSourcePointer{&s}.Data) // @Sink(em4)
}

func TestAll() {
	TestStructThatEmbedsSourceIsSource()
	TestStructThatEmbedsSourcePointerIsSource()
	TestEmbeddedSourceIsSource()
	TestEmbeddedSourcePointerIsSource()
}
