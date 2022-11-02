package main

// fmt.Sprintf is marked as source in config.yaml
import (
	"fmt"
	random "math/rand"
)

type Foo struct {
	Data string
}

// Bar is marked as source in config.yaml
type Bar struct {
	BarData string
}

type SomeStruct struct {
	DataField string // DataField is marked as source in config.yaml
	OtherData string
}

func (f Foo) zoo() bool {
	return len(f.Data) > 0
}

func mkBar() Bar {
	return Bar{BarData: "stuff"}
}

func mkSomeStruct() SomeStruct {
	return SomeStruct{DataField: "data", OtherData: "0"}
}

func sink1(interface{}) {
}

func sink2(ss *SomeStruct) {
	fmt.Println(ss.DataField)
}

func sink3(s string) {
	fmt.Println(s)
}

// ignore helper for ignoring unused variables
func ignore(...interface{}) {}

func part2() {
	y := Bar{BarData: "tainted"} // source
	y = mkBar()
	z := SomeStruct{DataField: y.BarData}
	sink3(z.DataField) // sink
	a := z.DataField
	b := z.OtherData
	sink3(a) // sink
	k := mkBar()
	sink3(k.BarData) // sink
	v := "something"
	k.BarData = v
	sink3(v)
	ignore(a, b)
}

func testChan() {
	y := mkBar()
	c := make(chan string)
	c <- y.BarData
	x := <-c
	sink3(x) // sink reached by y
}

func testChan2() {
	c := make(chan string)
	x := "_"
	if random.Int() > 10 {
		y := mkBar()
		c <- y.BarData
		x = <-c
	}
	sink3(x) // sink reached by y
}

func testChan3() {
	c := make(chan string, 11)
	c <- "notaint"
	sink3(<-c) // should not appear as sink receiving tainted value
	for i := 0; i < 10; i++ {
		y := mkBar()
		c <- y.BarData
	}
	for i := 0; i < 10; i++ {
		x := <-c
		sink3(x) // sink reached by y
	}
}

func testFlow1() {
	y := Bar{BarData: "tainted"} // source
	y = mkBar()
	z := SomeStruct{DataField: y.BarData}
	a := ""
	if random.Int() > 10 {
		for i := 0; i < 10; i++ {
			sink3(a)
			if random.Int() > 10 {
				a = z.DataField
			}
		}
	} else {
		sink3(a) // not sink
	}
}

func testFieldSensitivity() {
	x := mkSomeStruct()
	x.DataField = fmt.Sprintf("tainted")
	x.OtherData = "1"
	sink1(x.OtherData) // ok
	sink1(x.DataField) // sink
}

func simple1() {
	s := fmt.Sprintf("taintedstuff-%s", "fortest") // source
	x := Foo{Data: s}
	sink1(x)             // sink
	if b := x.zoo(); b { // source
		fmt.Println(x.Data)
		sink1(b) // sink
	}
}

func testFlow2() {
	a := ""
	if random.Int() > 10 {
		for i := 0; i < 10; i++ {
			sink3(a) // sink
			if random.Int() > 10 {
				y := Bar{BarData: "tainted"} // source
				y = mkBar()
				z := SomeStruct{DataField: y.BarData}
				a = z.DataField
			}
		}
	} else {
		sink3(a) // not sink
	}
}

func testAliasing1() {
	a := ""
	b := &a
	*b = fmt.Sprintf("x") // source
	sink3(a)              // sink
}

type example struct {
	ptr *string
}

func testAliasing2() {
	a := ""
	b := example{ptr: &a}
	*b.ptr = fmt.Sprintf("x") // source
	sink3(a)                  // sink
}

func testSlice() {
	a := []string{"a"}
	a = append(a, fmt.Sprintf("taint")) // Source
	sink3(a[1])                         // sink
}

type nestedStruct struct {
	Ex example
	A  string
}

func testNestedStructAliasing() {
	foo := []string{"a"}
	barex := example{&foo[0]}
	n := nestedStruct{Ex: barex, A: "b"}
	foo[0] = fmt.Sprintf("tainted") // source
	sink3(n.A)                      // ok
	sink3(*n.Ex.ptr)                // sink
}

func testMap() {
	a := make(map[int]string)
	a[0] = "a"
	sink3(a[0])                 // ok
	a[1] = fmt.Sprintf("taint") // source
	sink3(a[0])                 // sink
	a[2] = "b"
	sink3(a[2]) // sink (entire map is considered tainted)
}

func testMapAndFieldSensitivity() {
	a := make(map[int]string)
	x := mkSomeStruct()
	x.DataField = "a"
	x.OtherData = "1"
	a[0] = x.DataField
	sink3(a[0]) // ok
	x.DataField = fmt.Sprintf("taintedx")
	a[1] = x.DataField
	sink1(a[1]) // sink
}

func testReturnTaintedValue() string {
	a := make(map[int]string)
	x := mkSomeStruct()
	if random.Int() > 2 {
		x.DataField = "a"
		x.OtherData = "1"
		a[0] = x.DataField
	} else {
		x.DataField = fmt.Sprintf("tainted")
		a[1] = x.DataField
	}
	return a[1]
}

func testLongFunction() string {
	var ar [10]string
	xl := mkSomeStruct()
	for i := 0; i < 10; i++ {
		if random.Int() > 2 {
			xl.DataField = "ar"
			xl.OtherData = "1"
			ar[i] = xl.DataField
		} else {
			xl.DataField = fmt.Sprintf("tainted-value")
			ar[i] = xl.DataField
		}
	}
	sink1(ar[1])
	s := ar[1]
	ex := example{ptr: &s}
	switch *(ex.ptr) {
	case "tainted-value":
		sink3(*(ex.ptr)) //sink
		return "xl"
	default:
		return *(ex.ptr) // sink
	}
}

func testMapAndField2() {
	a := make(map[int]string)
	x := mkSomeStruct()
	x.DataField = fmt.Sprintf("tainted-testMapAndField2")
	x.OtherData = "b"
	a[0] = x.OtherData // not tainted
	sink1(a[0])        // should be ok
	a[1] = x.DataField // tainted
	sink1(a[1])        // source reaches sink here
}

func main() {
	simple1()
	part2()
	testFlow1()
	testFlow2()
	testChan()
	testChan2()
	testChan3()
	testFieldSensitivity()
	testAliasing1()
	testAliasing2()
	testSlice()
	testMap()
	testNestedStructAliasing()
	testMapAndFieldSensitivity()
	testMapAndField2()
	ignore(testReturnTaintedValue())
	ignore(testLongFunction())
}
