package main

// fmt.Sprintf is marked as source in config.yaml
import (
	"fmt"
)

type Stuff struct {
	Pickles string
}

func MkStuff() Stuff {
	return Stuff{
		Pickles: "...", // want "found a source"
	}
}

type Foo struct {
	Data string
}

// Bar is marked as source in config.yaml
type Bar struct {
	BarData string
}

type SomeStruct struct {
	DataField  string // DataField is marked as source in config.yaml
	OtherField int
}

// zoo is marked as source in config.yaml
func (f Foo) zoo() bool {
	return len(f.Data) > 0
}

func mkBar() Bar {
	return Bar{BarData: "stuff"} // want "found a source" "found a source"
}

func mkSomeStruct() SomeStruct {
	return SomeStruct{DataField: "data", OtherField: 0} // want "found a source"
}

// ignore helper for ignoring unused variables
func ignore(...interface{}) {}

func main() {
	s := fmt.Sprintf("taintedstuff-%s", "fortest") // want "found a source"
	x := Foo{Data: s}
	if x.zoo() { // want "found a source"
		fmt.Println(x.Data)
		fmt.Println(MkStuff().Pickles) // want "found a source"
	}
	y := Bar{BarData: "tainted"} // want "found a source" "found a source"
	y = mkBar()
	z := SomeStruct{DataField: "tainted"} // want "found a source"
	a := z.DataField                      // want "found a source"
	b := z.OtherField

	if len(mkSomeStruct().DataField) > 0 { // want "found a source"
		ignore(b, z)
	}

	ignore(y, z, a)
}
