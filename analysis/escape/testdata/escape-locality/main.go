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
	"fmt"
	"sync"
)

// This function represents a non-deterministic result. Because the analysis
// isn't boolean sensitive, we don't have to do anything fancy here.
func arbitrary() bool { return false }

type Node struct {
	next  *Node
	value string
}

var globalVar *Node = nil

func main() {
	testLocality()
	testLocality2()
	testRecursion()
	failInterproceduralLocality1()
	testInterproceduralLocality1()
	failInterproceduralLocality2()
	testDiamond()
	testAllInstructions(423)
	testExampleEscape7()
	testClosureFreeVar()
	testClosureFreeVar2()
	testClosureNonPointerFreeVar()
	testBoundMethod()
	testInterfaceMethodCall()
	testRationaleBasic()
	testRationaleUnknownReturn()
}

func testLocality2() {
	s := "a"
	x := &Node{&Node{nil, "ok"}, "ok"} // LOCAL
	go ex14foo(x.next)
	if x.next.next != nil {
		x.next.next.value = s // NONLOCAL
	}
}

func ex14foo(n *Node) {
	n.next = &Node{}
	fmt.Printf(n.next.value) // NONLOCAL
}

func testLocality() {
	x := &Node{}   // LOCAL
	x.next = nil   // LOCAL
	y := globalVar // NONLOCAL
	y.next = nil   // NONLOCAL
}

func accessLocal(n *Node) {
	n.value = "str" // LOCAL
}
func accessNonlocal(n *Node) {
	n.value = "str" // NONLOCAL
}
func accessBoth(n *Node) {
	n.value = "str" // BOTH
}

// This should fail the checks
func failInterproceduralLocality1() {
	n := &Node{}
	globalNode.next = n
	accessLocal(n)
}

func testInterproceduralLocality1() {
	n := &Node{}
	accessLocal(n)
}

func failInterproceduralLocality2() {
	n := &Node{}
	accessNonlocal(n)
}

func diamondLeft(n *Node) {
	accessBoth(n)
}
func diamondRight(n *Node) {
	accessBoth(n)
}
func testDiamond() {
	l := &Node{}
	r := &Node{}
	globalNode.next = r
	diamondLeft(l)
	diamondRight(r)
}

func source() string {
	return "G"
}
func sink(s string) {
	fmt.Printf("Sink: %v\n", s)
}

var globalNode = Node{nil, "g"}

func testRecursion() {
	// Lock to ensure program doesn't have a data race
	var mu sync.Mutex
	mu.Lock()
	go func() {
		globalNode.value = source()
		mu.Unlock()
	}()
	mu.Lock()
	x := &Node{&Node{&globalNode, "2"}, "1"}
	c := recursiveConcat(x)
	sink(c)
}

// In the context where it is called from testRecursion, the params are:
//
//	n --> Node{"1"} --> Node{"2"} --> global
//
// where n and both Nodes are local, and global is external.
// The first recursive call gives us:
//
//	n --> Node{"2"} --> global
//
// If we stop here and do not consider more contexts, we would conclude
// that n.value is always local, but n can refer to global, and thus the
// load n.value can be non-local.
func recursiveConcat(n *Node) string {
	if n == nil {
		return ""
	}
	r := n.value
	r += recursiveConcat(n.next)
	return r
}

func leak(p *string) {
	// pkgGlobal = p
}

// in standard library:
func notBad(x string, p *string) {
	*p = x
	leak(p)
}
func veryBad(x string, p *string) {
	y := "abc"
	q := &y
	*q = x
	leak(q)
}

func testExampleEscape7() {
	x := &Node{&Node{&Node{nil, "3"}, "2"}, "1"}
	ex7foo(x.next)
}

func ex7foo(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next // LOCAL
	_ = n2.value // LOCAL
}

func leakNode(n *Node) {
	globalNode.next = n
}
func dontLeakNode(n *Node) {
}

type NodeWrapper Node

func returnInts() (int, int) {
	return 1, 2
}

type A interface {
	Afunc(int) int
}
type B interface {
	Afunc(int) int
	Bfunc(int) int
}
type Bstruct struct {
	x int
}

var bstructGlobal *Bstruct = nil
var globalIntChan chan int = nil
var globalMapStrStr map[string]string = nil

func (b *Bstruct) Afunc(x int) int {
	return b.x + x
}
func (b *Bstruct) Bfunc(x int) int {
	return b.x * x
}

func returnNodeStruct() *Node {
	return &Node{nil, "hi"}
}
func returnArray() [2]int {
	return [2]int{1, 2}
}

func testAllInstructions(x int) {
	// Alloc
	local := &Node{} // LOCAL
	// BinOp
	var y = x + 2  // LOCAL
	var z = y <= 2 // LOCAL
	_ = z
	// Call
	nonlocal := &Node{} // LOCAL
	leakNode(nonlocal)  // NONLOCAL
	dontLeakNode(local) // NONLOCAL
	// ChangeInterface
	binter := (B)(&Bstruct{2})                // LOCAL
	var _ = (any)(binter)                     // LOCAL
	var _ = (A)(binter)                       // LOCAL
	var _ = (B)(binter)                       // LOCAL
	bstructNonlocal := &Bstruct{3}            // LOCAL
	bstructGlobal = bstructNonlocal           // NONLOCAL
	var binterNonlocal = (B)(bstructNonlocal) // LOCAL
	var _ = (A)(binterNonlocal)               // LOCAL
	var _ = (any)(binterNonlocal)             // LOCAL
	// ChangeType
	var _ = (NodeWrapper)(*local) // LOCAL
	var _ = (*NodeWrapper)(local) // LOCAL
	// Involves a read:
	var _ = (NodeWrapper)(*nonlocal) // NONLOCAL
	var _ = (*NodeWrapper)(nonlocal) // LOCAL
	// Convert
	valF := 0.5                     // LOCAL
	var _ = (int)(valF)             // LOCAL
	byteslice := []byte{54, 23, 34} // LOCAL
	s := (string)(byteslice)        // LOCAL
	_ = ([]byte)(s)                 // LOCAL
	// DebugRef
	// no test, as doesn't appear in our SSA
	// Defer
	defersTest()
	// Extract
	// This might be hard to test as getting the extract by itself isn't easy
	a, b := returnInts()
	a = b // LOCAL
	b = a // LOCAL
	// Field
	// instruction split so the .local and the function call can have different annotations
	nodeRet := returnNodeStruct()
	_ = nodeRet.value
	_ = returnNodeStruct(). // NONLOCAL
				value // LOCAL
	// FieldAddr
	// First one is FieldAddr and Load, second/third are FieldAddr only
	_ = local.next     // LOCAL
	_ = &local.next    // LOCAL
	_ = &nonlocal.next // LOCAL
	// Go
	node1 := &Node{}
	node2 := &Node{}
	go dontLeakNode(node1) // NONLOCAL
	// If
	if a == x { // LOCAL
		dontLeakNode(node1)
	} else {
		dontLeakNode(node2)
	}
	// Index
	// TODO: this test can't quite test the right thing as we need a function
	// call to get an Index instruction, but calls are always non-local so
	// we can't enforce that the Index operation itself is nonlocal. There
	// doesn't appear to be a way to split the line without automatically
	// getting a ; inserted, either.
	_ = returnArray()[ // NONLOCAL
	1]                 // LOCAL

	// IndexAddr
	intSlice := []int{1, 2, 3, 4}  // LOCAL
	intArray := [4]int{1, 2, 3, 4} // LOCAL
	_ = &intSlice[1]               // LOCAL
	_ = &intArray[1]               // LOCAL
	// Jump
	// TODO: How to annotate this instruction in the SSA?
	// Lookup
	mapStrStr := map[string]string{"a": "1", "b": "2"}
	nonlocalMapStrStr := map[string]string{"a": "1", "b": "2"}
	globalMapStrStr = nonlocalMapStrStr
	_ = mapStrStr["a"]         // LOCAL
	_ = nonlocalMapStrStr["a"] // NONLOCAL
	// MakeChan
	localChan := make(chan int)    // LOCAL
	nonlocalChan := make(chan int) // LOCAL
	globalIntChan = nonlocalChan
	// MakeClosure
	_ = func() { // LOCAL
		nonlocal.next.value = "2"
	}
	// MakeInterface
	_ = (any)(local)       // LOCAL
	_ = (any)(nonlocal)    // LOCAL
	_ = (B)(&Bstruct{2})   // LOCAL
	_ = (A)(&Bstruct{2})   // LOCAL
	_ = (any)(&Bstruct{2}) // LOCAL
	// MakeMap
	_ = make(map[int]string) // LOCAL
	// MakeSlice
	_ = make([]int, 5, 10) // LOCAL
	// MapUpdate
	mapStrStr["a"] = "x"         // LOCAL
	nonlocalMapStrStr["a"] = "x" // NONLOCAL
	// MultiConvert
	// This doesn't show up in our SSA
	// Next
	for _ = range nonlocalMapStrStr { // NONLOCAL

	}
	for _ = range mapStrStr { // LOCAL

	}
	// Panic
	testPanic()
	// Phi
	// This operation can't be annotated
	// Range
	for _ = range nonlocalMapStrStr { // NONLOCAL

	}
	for _ = range mapStrStr { // LOCAL

	}
	// Return
	returnTest()
	// RunDefers
	defersTest()
	// Select
	// TODO: is this correctly tested?
	select {
	case <-nonlocalChan: // NONLOCAL
		dontLeakNode(nonlocal)
	}
	select { // NONLOCAL
	case <-nonlocalChan:
		dontLeakNode(nonlocal)
	case <-localChan:
		dontLeakNode(nonlocal)
	}
	select { // LOCAL
	case <-localChan: // LOCAL
		dontLeakNode(nonlocal)
	}
	// Send
	localChan <- 4    // LOCAL
	nonlocalChan <- 6 // NONLOCAL
	// Slice
	_ = intSlice[1:2] // LOCAL
	// SliceToArrayPointer
	_ = (*[2]int)(intSlice[1:2]) // LOCAL
	// Store
	local.value = "a"    // LOCAL
	nonlocal.value = "B" // NONLOCAL
	// TypeAssert
	_, ok := binterNonlocal.(*Bstruct) // NONLOCAL
	_, ok = binter.(*Bstruct)          // LOCAL
	_ = ok
	// UnOp
	// recv
	_ = <-localChan    // LOCAL
	_ = <-nonlocalChan // NONLOCAL
	// load
	_ = nonlocal.next // NONLOCAL
	_ = local.next    // LOCAL
	// arithmetic
	_ = -x // LOCAL
}

func returnTest() *Node {
	return &globalNode // LOCAL
}

func defersTest() {
	defer func() {}() // LOCAL
	return            // LOCAL
}

func testPanic() {
	panic("hi") // LOCAL
}

func callF(f func(*Node) *Node, b *Node) {
	x := f(b)
	x.next = nil // NONLOCAL
}

func testClosureFreeVar() {
	a := &Node{}
	b := &Node{}
	f := func(b *Node) *Node {
		a.next = b // NONLOCAL
		return b
	}
	leakNode(a)
	callF(f, b)
	b.value = "3" // NONLOCAL
}

func callF2(f func(*Node) *Node, b *Node) {
	x := f(b)
	x.next = nil // LOCAL
}
func testClosureFreeVar2() {
	a := &Node{}
	b := &Node{}
	f := func(b *Node) *Node {
		leakNode(a)
		return b
	}
	callF2(f, b)
	a.value = "1" // NONLOCAL
	b.value = "2" // LOCAL
}

func callF3(f func(*Node, int) *Node, b *Node) {
	x := f(b, 32)
	x.next = nil // LOCAL
}
func testClosureNonPointerFreeVar() {
	a := &Node{}
	b := &Node{}
	x := 4
	f := func(b *Node, y int) *Node {
		leakNode(a)
		x += y
		return b
	}
	callF3(f, b)
	a.value = "1" // NONLOCAL
	b.value = "2" // LOCAL
}

func indirectFunc(f func(*Node)) {
	f(&Node{})
}

type Assigner struct {
	a *Node
}

func (a *Assigner) assign(b *Node) {
	a.a.next = b // NONLOCAL
}

func testBoundMethod() {
	a := &Assigner{&Node{}}
	f := a.assign
	globalNode.next = a.a
	indirectFunc(f)
}

type Inter interface {
	DoSomething(*Node)
}

type InterImpl1 struct {
	a int
}

func (i *InterImpl1) DoSomething(n *Node) {
	i.a = 1
	if n != nil {
		leakNode(n)
	}
}

type InterImpl2 struct {
	b int
}

func (i *InterImpl2) DoSomething(n *Node) {
	i.b = 2 // LOCAL
}
func innerCallMethod(i Inter) {
	i.DoSomething(nil)
}
func testInterfaceMethodCall() {
	i := &InterImpl2{}
	innerCallMethod(i)
}

// Tests that the rationales are correct. The test ensures the rationale has the given substring
func testRationaleBasic() {
	x := &Node{}
	globalNode.next = x
	_ = x.next // NONLOCAL global *globalNode

	y := &Node{}
	go dontLeakNode(y)
	y.next = nil // NONLOCAL argument to go
}

// The config should prevent the analysis from seeing the body of this function, so the return value
// will be an "unknown node"
func unknownFunc() *Node {
	return &Node{}
}

func testRationaleUnknownReturn() {
	x := unknownFunc()
	_ = x.next // NONLOCAL unknown return of github.com/awslabs/ar-go-tools/analysis/escape/testdata/escape-locality.unknownFunc
}
