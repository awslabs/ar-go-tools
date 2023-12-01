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

// This is a no-op, but calls are checked by the test harness to check
// the set of edges from x and y are the same (i.e. they have the SameAliases).
func assertSameAliases(x, y any) {}

// Same, but asserts that all edges are to nodes that have leaked
func assertAllLeaked(x any) {}

// Same, but asserts all pointees are local (not escaped or leaked)
func assertAllLocal(x any) {}

type Node struct {
	next *Node
}

var globalVar *Node = nil

func main() {
	testAlias()
	inverseAlias()
	inverseLeaked()
	inverseLocal()
	inverseLocalEscapedOnly(&Node{})
	testTraverseList()
	testTraverseListRecur()
	testStepLargeList()
	testMultiReturnValues()
	testConsume()
	testFresh()
	testIdent()
	testExternal()
	testChain()
	testStickyErrorReader()
	testMutualInterfaceRecursion()
	testFunctionPointerReturn()
	testOrdinaryFunction()
	testBoundMethodFuncPointer()
	testAbstractFunction()
}

// Basic test of the assertSameAliases function
func testAlias() {
	x := &Node{nil}
	assertSameAliases(x, x) // This should succeed
}

// Meta-test that the assertSameAliases function does the right thing
// functions that do not start with test succeed if they raise an error
func inverseAlias() {
	x := &Node{nil}
	y := &Node{nil}
	assertSameAliases(x, y) // This should fail
}

// Meta-test that the assertAllLeaked function checks for leaks
func inverseLeaked() {
	x := &Node{nil}
	assertAllLeaked(x) // This should fail
}

// Meta-test that the assertAllLocal function fails on leaked nodes
func inverseLocal() {
	x := &Node{nil}
	globalVar = x
	assertAllLocal(x) // This should fail
}

// Meta-test that the assertAllLocal function fails on escaped but not leaked nodes
func inverseLocalEscapedOnly(x *Node) {
	assertAllLocal(x) // This should fail
}

func loop(n *Node) *Node {
	for {
		nn := n.next
		if nn != nil {
			n = nn
		} else {
			return n
		}
	}
}

// Test that a loop function will give the only node in a linked list of size 1
func testTraverseList() *Node {
	x := &Node{nil}
	y := loop(x)
	assertSameAliases(x, y)
	return y
}

func loopRecur(n *Node) *Node {
	nn := n.next
	if nn != nil {
		return loopRecur(nn)
	} else {
		return n
	}
}

// Test the invocation of a recursive function
func testTraverseListRecur() *Node {
	x := &Node{&Node{}}
	y := loopRecur(x)
	z := x
	if arbitrary() {
		z = z.next
	}
	assertSameAliases(y, z) // z = x or x.next
	return y
}

func oneStep(n *Node) *Node {
	return n.next
}

// Tests that multiple function calls compose together, and also that field lookups work correctly
func testStepLargeList() *Node {
	x0 := &Node{nil}
	x1 := &Node{x0}
	x2 := &Node{x1}
	y := oneStep(oneStep(x2))
	assertSameAliases(y, x0)
	assertSameAliases(x0, x2.next.next)
	return y
}

func nodeAndNext(n *Node) (*Node, *Node) {
	return n, n.next
}

// This test is disabled until we support tuple-sensitivity
func testMultiReturnValues() *Node {
	x := &Node{nil}
	y := &Node{x}
	_, b := nodeAndNext(y)
	// assertSameAliases(x, b)
	return b
}

func identity(n *Node) *Node {
	return n
}

// Test that the summary of the identity function correctly returns its argument
func testIdent() *Node {
	x := &Node{nil}
	y := identity(x)
	assertSameAliases(x, y)
	return y
}

func fresh() *Node {
	x := &Node{nil}
	assertAllLocal(x)
	return x
}

// Test that a function that allocates an object produces a local object
func testFresh() *Node {
	x := fresh()
	assertAllLocal(x)
	return x
}

func consume(n *Node) {
	globalVar = n
}

// Tests that calling a function that leaks propagates into the caller
func testConsume() *Node {
	x := &Node{}
	consume(x)
	assertAllLeaked(x)
	return x
}

// Test that a call to an external function leaks its arguments.
// Due to the way printf works this also tests slices
func testExternal() error {
	x := &Node{}
	_, err := fmt.Printf("Value: %v\n", x)
	assertAllLeaked(x)
	return err
}

func chainExtend(a *Node, b *Node) {
	a.next.next.next = b
}
func chainExtendWrapper(a *Node, b *Node) {
	chainExtend(a, b)
}
func testChain() {
	a := &Node{&Node{&Node{}}}
	b := &Node{}
	chainExtendWrapper(a, b)
	globalVar = a
	assertAllLeaked(b)
}

type Reader interface {
	Read(p []byte) (n int, err error)
}

type stickyErrorReader struct {
	r   Reader
	err error
}

type simpleReader struct {
	data []byte
}

func (r *stickyErrorReader) Read(p []byte) (n int, _ error) {
	// if r.err != nil {
	// 	return 0, r.err
	// }
	n, r.err = r.r.Read(p)
	return n, r.err
}
func (r *simpleReader) Read(p []byte) (n int, _ error) {
	return copy(p, r.data), nil
}

func testStickyErrorReader() {
	baseReader := &simpleReader{([]byte("alsdfja;s'd"))}
	x := len(baseReader.data)
	var r Reader = nil // &stickyErrorReader{baseReader, nil}
	for i := 0; i < x; i++ {
		r = &stickyErrorReader{r, nil}
	}
	p := []byte{0, 0, 0, 0}
	r.Read(p)
}

type ActionInterface interface {
	DoSomething(*Node) *Node
}

type Impl1 struct {
	i ActionInterface
}

func (i *Impl1) DoSomething(n *Node) *Node {
	return i.i.DoSomething(n)
}

type Impl2 struct {
	i ActionInterface
}

func (i *Impl2) DoSomething(n *Node) *Node {
	return i.i.DoSomething(n)
}

type Impl3 struct {
	i ActionInterface
}

func (i *Impl3) DoSomething(n *Node) *Node {
	return i.i.DoSomething(n)
}

type Impl4 struct {
	i ActionInterface
}

func (i *Impl4) DoSomething(n *Node) *Node {
	return i.i.DoSomething(n)
}

func getImpl() ActionInterface {
	if arbitrary() {
		return &Impl1{getImpl()}
	} else if arbitrary() {
		return &Impl2{getImpl()}
	} else if arbitrary() {
		return &Impl3{getImpl()}
	} else {
		return &Impl4{getImpl()}
	}
}

// Test whether the size of the graph blows up for recursive interfaces
func testMutualInterfaceRecursion() {
	x := getImpl()
	x.DoSomething(&Node{})
}

type Value struct {
}
type Type struct {
}
type encodeState struct {
}

func (v *Value) IsValid() bool {
	return true
}

func (v *Value) Type() Type {
	return Type{}
}

type encoderFunc func(e *encodeState, v Value)

func (e *encodeState) reflectValue(v Value) {
	valueEncoder(v)(e, v)
}

func valueEncoder(v Value) encoderFunc {
	if !v.IsValid() {
		return invalidValueEncoder
	}
	return typeEncoder(v.Type())
}

func typeEncoder(t Type) encoderFunc {
	if fi, ok := encoderCache.Load(t); ok {
		return fi.(encoderFunc)
	}

	// To deal with recursive types, populate the map with an
	// indirect func before we build it. This type waits on the
	// real func (f) to be ready and then calls it. This indirect
	// func is only used for recursive types.
	var (
		wg sync.WaitGroup
		f  encoderFunc
	)
	wg.Add(1)
	fi, loaded := encoderCache.LoadOrStore(t, encoderFunc(func(e *encodeState, v Value) {
		wg.Wait()
		f(e, v)
	}))
	if loaded {
		return fi.(encoderFunc)
	}

	// Compute the real encoder and replace the indirect func with it.
	f = newTypeEncoder(t, true)
	wg.Done()
	encoderCache.Store(t, f)
	return f
}
func invalidValueEncoder(e *encodeState, v Value) {

}

type structEncoder struct {
}

func newTypeEncoder(t Type, _ bool) encoderFunc {
	se := structEncoder{}
	return se.encode
}

func (se structEncoder) encode(e *encodeState, v Value) {
}

var encoderCache sync.Map // map[reflect.Type]encoderFunc

func testFunctionPointerReturn() {
	e := &encodeState{}
	e.reflectValue(Value{})
	newTypeEncoder(Type{}, false)(e, Value{})
}

func leakGlobally(n *Node) {
	globalVar.next = n
}
func getSomeFunc() func(*Node) {
	return leakGlobally
}
func testOrdinaryFunction() {
	n := &Node{}
	getSomeFunc()(n)
	assertAllLeaked(n)
}

type LeakingStruct struct {
	dest **Node
}

func (l *LeakingStruct) leak(n *Node) {
	*l.dest = n
}
func globalLeaker() func(*Node) {
	x := &LeakingStruct{&globalVar}
	return x.leak
}
func testBoundMethodFuncPointer() {
	f := globalLeaker()
	x := &Node{}
	f(x)
	assertAllLeaked(x)
}

func callTwice(f func(n *Node) *Node, n *Node) {
	f(n)
	f(n)
}
func testAbstractFunction() {
	var f1, f2 func(*Node) *Node
	{
		var x *Node = nil
		f1 = func(n *Node) *Node {
			x = n
			_ = x
			return nil
		}
	}
	{
		var x *Node = nil
		f2 = func(n *Node) *Node {
			globalVar.next = x
			return nil
		}
	}
	y := &Node{}
	if arbitrary() {
		f1 = f2
	}
	callTwice(f1, y)
	assertAllLocal(y)
}
