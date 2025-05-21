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
	testMethod()
	testVarargs()
	testNilArg()
	testVariousBuiltins()
	testGo()
	testAppend([]*Node{})
	testIndexArray()
	testChannel()
	testChannelEscape()
	testChannelStruct()
	testSelect()
	testConvertStringToSlice()
	testImmediateClosure1()
	testImmediateClosure2()
	testLocalVarClosure1()
	testLocalVarClosure2()
	testLocalVarClosure3()
	testLeakOfFunc()
	testCalleeClosure1()
	testCalleeClosure2()
	testGlobalFunc1()
	testGlobalFunc2()
	testGlobalFunc3()
	testMethodOfLocal()
	testBoundMethodOfLocal1()
	testBoundMethodOfLocal2()
	testBoundMethodOfLocal3()
	testMethodNonPointer1()
	testMethodNonPointer2()
	testFuncStruct()
	testFuncStructArg()
	testMethodOnNonTracked1()
	testMethodOnNonTracked2()
	testNonPointerFreeVar()
	testMultipleBoundVars()
	testSiblingClosure()
	testInterfaceDirectStruct()
	testFieldSensitivity()
	testTupleSensitivity()
	testSlicing(23)
	testParameterPointerToField()
	testStructSelfPointerToField()
	testNestedStruct()
	testForRange()
	testTypeCorrectness()
	testGoReceiver()
	testMultiChannelSelect()
	testInterfaces()
	testInterfaces2()
	testInterfaces3()
	testMockDocument()
}

func (n *Node) loopMethod(iters int) *Node {
	for {
		nn := n.next
		if nn != nil {
			n = nn
		} else {
			return n
		}
	}
}
func (n *Node) setNext(next *Node) {
	n.next = next
}

type SetNextable interface {
	setNext(next *Node)
}

type myError struct{ error }

func testMethod() {
	x := &Node{nil}
	y := x.loopMethod(0)
	assertSameAliases(x, y)

	x.setNext(x)
	assertSameAliases(x, x.next)
	var z SetNextable = x
	z.setNext(x)

	var err myError
	err.Error()
}

func printlike(fmt string, args ...string) {

}
func testVarargs() {
	// printlike("hi")
	printlike("one %s", "a")
	printlike("two %s %s", "a", "b")
}

func funcOfNode(n *Node) {

}
func funcOfNodeReturningNode(n *Node) *Node {
	return n
}
func testNilArg() {
	funcOfNode(nil)
	var x *Node
	assertSameAliases(nil, x)
}

func testGo() {
	x := &Node{}
	go funcOfNode(x)
	assertAllLeaked(x)
	y := &Node{}
	go funcOfNodeReturningNode(y) // check returning a pointer-like (should be like `_ := f()`)
	assertAllLeaked(y)

}
func testVariousBuiltins() int {
	x := make([]int, 5)
	l := len(x)

	// New is lowered to one of the Make*/Alloc instructions plus "address of"
	y := new(Node)
	z := new(int)
	w := new(chan int)
	assertAllLocal(y)
	assertAllLocal(z)
	// w is a *chan int, so a pointer to a heap cell containing the pointer-like channel
	// reference. Ensure both are local
	assertAllLocal(w)
	assertAllLocal(*w)

	return l
}

func testAppend(s []*Node) []*Node {
	s = append(s, &Node{})
	// Test multiple append arguments
	s = append(s, &Node{}, &Node{})
	return s
}

var globalArray = [...]*Node{
	nil, nil, nil,
}

func testIndexArray() {
	x := &Node{}
	y := &Node{}
	arr := [2]*Node{x, y}
	z := arr[0]
	w := y
	if arbitrary() {
		w = x
	}
	assertSameAliases(z, w)
	a := &globalArray[0]
	assertAllLeaked(a)
}
func recv(ch chan *Node) *Node {
	return <-ch
}
func testChannel() {
	x := &Node{}
	ch := make(chan *Node, 1)
	ch <- x
	y := recv(ch)
	assertSameAliases(x, y)
	assertAllLocal(x)
	assertAllLocal(ch)
}

func testChannelEscape() {
	x := &Node{}
	ch := make(chan *Node, 1)
	ch <- x
	go recv(ch)
	assertAllLeaked(x)
}

func testChannelStruct() {
	z := &Node{}
	x := Node{z}
	ch := make(chan Node, 1)
	ch <- x
	y := <-ch
	globalVar = y.next
	assertAllLeaked(z)
}

func testSelect() {

	x := &Node{}
	y := &Node{}
	ch := make(chan *Node, 1)
	select {
	case ch <- x:

	case ch <- y:

	}
	w := x
	if arbitrary() {
		w = y
	}
	select {
	case z := <-ch:
		assertSameAliases(z, w)
		assertAllLocal(z)
	default:

	}
}

func testConvertStringToSlice() {
	x := "abc"
	y := []byte(x)
	assertAllLocal(y)
	z := []rune(x)
	assertAllLocal(z)
	w := x[:]
	assertAllLocal(w)
}

func testImmediateClosure1() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	assertAllLeaked(a)
	func(a, b *Node) {
		a.next = b
	}(a, b)
	assertAllLeaked(b)
}

func testImmediateClosure2() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	assertAllLeaked(a)
	func() {
		a.next = b
	}()
	assertAllLeaked(b)
}

func testLocalVarClosure1() {
	a := &Node{}
	b := &Node{}
	x := func() {
		a.next = b
	}
	globalVar.next = a
	assertAllLeaked(a)
	x()
	assertAllLeaked(b)
}

func testLocalVarClosure2() {
	a := &Node{}
	b := &Node{}
	x := func() {
		a.next = b
	}
	y := func() {
		a.next = b
	}
	globalVar.next = a
	assertAllLeaked(a)
	var z func()
	if arbitrary() {
		z = x
	} else {
		z = y
	}
	// This just forces z() to not be a
	z()
	assertAllLeaked(b)
}

func testLocalVarClosure3() {
	a := &Node{}
	b := &Node{}
	c := &Node{}
	x := func(b, c *Node) {
		a.next = b
	}
	y := func(b, c *Node) {
		a.next = c
	}
	globalVar.next = a
	assertAllLeaked(a)
	var z func(*Node, *Node)
	if arbitrary() {
		z = x
	} else {
		z = y
	}
	// Test that we can have both a.next = b and a.next = c on this line
	// This makes sure that the results of applying all summaries are merged,
	// as in this test either b or c is leaked individually by each func.
	z(b, c)
	assertAllLeaked(b)
	assertAllLeaked(c)
}

// global var for funcs
var callback func()

func testLeakOfFunc() {
	a := &Node{}

	x := func() {
		a.next = a
	}
	// This leaks a because the closure has a reference to a
	callback = x
	assertAllLeaked(a)
	callback()
}

func getAssignerFunc(a *Node) func(*Node) {
	return func(b *Node) {
		a.next = b
	}
}

// Test that a closure returned from a callee performs the given assignment
func testCalleeClosure1() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	f := getAssignerFunc(a)
	f(b)
	assertAllLeaked(b)
}

// The same as above, but without a leaked value
func testCalleeClosure2() {
	a := &Node{}
	b := &Node{}
	f := getAssignerFunc(a)
	f(b)
	assertAllLocal(b)
}

func fieldAssigner(a, b *Node) {
	a.next = b
}
func noFieldAssigner(a, b *Node) {

}

var globalNodeProcessorFunc func(a, b *Node)

// Test that pointers to functions work, and that the correct
// implementations are picked up from the pointer analysis
func testGlobalFunc1() {
	globalNodeProcessorFunc = fieldAssigner
	a := &Node{}
	b := &Node{}
	globalNodeProcessorFunc(a, b)
	assertAllLocal(b)
}
func testGlobalFunc2() {
	globalNodeProcessorFunc = fieldAssigner
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	globalNodeProcessorFunc(a, b)
	assertAllLeaked(b)
}

// Tests that the variable could still point to field assigner, even though
// that can't actually happen in this program
func testGlobalFunc3() {
	globalNodeProcessorFunc = noFieldAssigner
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	// The analysis should still conclude that `a.next=b`` could be executed
	globalNodeProcessorFunc(a, b)
	assertAllLeaked(b)
}

type Assigner struct {
	a *Node
}

func (a *Assigner) assign(b *Node) {
	a.a.next = b
}
func testMethodOfLocal() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	assigner := Assigner{a}
	assigner.assign(b)
	assertAllLeaked(b)
}

func identityForFuncOfNode(x func(*Node)) func(*Node) {
	return x
}
func identityForFuncOfNothing(x func()) func() {
	return x
}

func testBoundMethodOfLocal1() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	assigner := Assigner{a}
	// Force processing though non-local means
	f := identityForFuncOfNode(func(b *Node) { assigner.assign(b) })
	f(b)
	assertAllLeaked(b)
}

func testBoundMethodOfLocal1b() {
	a := &Node{}
	b := &Node{}
	globalVar.next = a
	assigner := Assigner{a}
	// Force processing though non-local means
	f := identityForFuncOfNode(assigner.assign)
	f(b)
	assertAllLeaked(b)
}
func testBoundMethodOfLocal2() {
	a := &Node{}
	b := &Node{}
	assigner := Assigner{a}
	// The bound method leaks, but call it directly
	f := assigner.assign
	assertAllLocal(b)
	f(b)
	// Here is where b leaks
	funcForBoundMethodTestOnly = f
	assertAllLeaked(b)
}

var funcForBoundMethodTestOnly func(*Node)

func testBoundMethodOfLocal3() {
	a := &Node{}
	b := &Node{}
	assigner := Assigner{a}
	f := assigner.assign
	funcForBoundMethodTestOnly = f
	// Test that the leak still happens even if f is invoked directly
	f(b)
	assertAllLeaked(b)
}

type someStruct struct {
	n *Node
}

func (s someStruct) MethodOnNonPointer() error {
	s.n = &Node{}
	return nil
}
func (s someStruct) MethodThatLeaks() {
	globalVar = s.n
}

func funcThatReturnsStructDirectly() someStruct {
	return someStruct{globalVar}
}
func funcThatReturnsPointer() *someStruct {
	return &someStruct{globalVar}
}

func testMethodNonPointer1() {
	a := &Node{}
	s := someStruct{a}
	s.MethodOnNonPointer()
	s.MethodThatLeaks()
	assertAllLeaked(a)
}
func testMethodNonPointer2() {
	a := &Node{}
	// Now s is a pointer, but the method is defined on the original
	s := &someStruct{a}
	s.MethodOnNonPointer()
	s.MethodThatLeaks()
	assertAllLeaked(a)
}

func testFuncStruct() {
	a := funcThatReturnsStructDirectly().n
	b := funcThatReturnsPointer().n
	assertAllLeaked(a)
	assertAllLeaked(b)
}

func funcWithDirectStructArg(s someStruct) {
	globalVar = s.n
}

func testFuncStructArg() {
	a := &Node{}
	s := someStruct{a}
	funcWithDirectStructArg(s)
	assertAllLeaked(a)
}

type A int

func (a A) Method() *Node {
	return globalVar
}

type MethodInterface interface {
	Method() *Node
}

func testMethodOnNonTracked1() {
	var x A
	b := x.Method()
	assertAllLeaked(b)
}

func testMethodOnNonTracked2() {
	var x MethodInterface = new(A)
	b := x.Method()
	assertAllLeaked(b)
}

func testNonPointerFreeVar() {
	x := 5
	f := func() {
		x += 5
	}
	identityForFuncOfNothing(f)()
}

func callFunc(f func()) {
	f()
}
func testMultipleBoundVars() {
	a := &Node{}
	b := &Node{}
	f := func() {
		a.next = b
	}
	callFunc(f)
	globalVar = a
	assertAllLeaked(a)
	assertAllLeaked(b)
}

func makeClosureToLeak(n *Node) func() {
	return func() { globalVar = n }
}
func callFunc2(f func()) {
	f()
}
func testSiblingClosure() {
	a := &Node{}
	callFunc2(makeClosureToLeak(a))
	assertAllLeaked(a)
}

type DoInterface interface {
	thingMethod()
}

type thingDoer struct {
	a *Node
}

func (t thingDoer) thingMethod() {
	globalVar = t.a
}

func doThing(d DoInterface) {
	d.thingMethod()
}

// The same as above, but for a pointer receiver
type thingDoer2 struct {
	a *Node
}

func (t *thingDoer2) thingMethod() {
	globalVar = t.a
}

func doThing2(d DoInterface) {
	d.thingMethod()
}

func testInterfaceDirectStruct() {
	a := &Node{}
	thing := thingDoer{a}
	doThing(thing)
	assertAllLeaked(a)
	b := &Node{}
	thing2 := &thingDoer2{b}
	doThing2(thing2)
	assertAllLeaked(b)
}

type MultiField struct {
	a *Node
	b *int
	c *Node
}

func testFieldSensitivity() {
	mf := &MultiField{}
	mf.a = &Node{}
	assertSameAliases(mf.b, nil)
}

func swap(a, b *Node) (x, y *Node) {
	return b, a
}
func testTupleSensitivity() {
	a := &Node{}
	b := &Node{}
	x, y := swap(a, b)
	assertSameAliases(a, y)
	assertSameAliases(b, x)
}

func testSlicing(nzone int) ([]byte, []byte) {
	b := make([]byte, nzone)
	c := make([]byte, 5)
	x := &b
	_ = c
	return *x, []byte{2}
}

type nodeHolder struct {
	a, b *Node
}

func writeToSomeFieldViaPointer(fieldPointer **Node, value *Node) {
	*fieldPointer = value
}
func testParameterPointerToField() {
	x := &Node{}
	y := &Node{}
	n := &nodeHolder{nil, nil}
	n.b = y
	writeToSomeFieldViaPointer(&n.a, x)
	assertSameAliases(x, n.a)
	assertSameAliases(y, n.b)
}

type selfPointerStruct struct {
	n              *Node
	nodeDblPointer **Node
}

func newSelfReference() *selfPointerStruct {
	x := &selfPointerStruct{}
	x.nodeDblPointer = &x.n
	return x
}
func testStructSelfPointerToField() {
	x := newSelfReference()
	y := &Node{}
	writeToSomeFieldViaPointer(x.nodeDblPointer, y)
	// check that the write went to x.n
	assertSameAliases(x.n, y)
}

type nestedStruct struct {
	a *Node
	b nodeHolder
}

func returnNestedStruct(a, ba, bb *Node) nestedStruct {
	return nestedStruct{a, nodeHolder{ba, bb}}
}
func getFieldA(n nestedStruct) *Node {
	return n.a
}
func getFieldBB(n nestedStruct) *Node {
	return n.b.b
}
func testNestedStruct() {
	x, y, z := &Node{}, &Node{}, &Node{}
	n := returnNestedStruct(x, y, z)
	assertSameAliases(n.a, x)
	assertSameAliases(n.b.a, y)
	assertSameAliases(n.b.b, z)
	n2 := nestedStruct{x, nodeHolder{y, z}}
	assertSameAliases(getFieldA(n2), x)
	assertSameAliases(getFieldBB(n2), z)
}

func mapKV(m map[*Node]*Node) (*Node, *Node) {
	for k, v := range m {
		return k, v
	}
	return nil, nil
}
func mapKVintValue(m map[*Node]int) (*Node, int) {
	for k, v := range m {
		return k, v
	}
	return nil, 0
}

func testForRange() {
	x := &Node{}
	y := &Node{}

	m := map[*Node]*Node{x: y}
	z, w := mapKV(m)
	assertSameAliases(x, z)
	assertSameAliases(y, w)

	m2 := map[*Node]int{}
	x = &Node{}
	m2[x] = 4
	for x := range m2 {
		_ = x
	}
	z2, _ := mapKVintValue(m2)
	assertSameAliases(x, z2)
}

func testTypeCorrectness() {
	x := make([]int, 5)
	var p *int = &x[2]
	*p = 4

	in := "asdkfja;"
	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	z := string(out)
	_ = z
}

func testGoReceiver() *Node {
	x := &Node{}
	go func() {
		x.next = &Node{}
	}()
	assertAllLeaked(x.next) // It should not be local
	return x
}

func multiSelect(c1 chan *Node, c2 chan *nodeHolder) (*Node, *nodeHolder) {
	select {
	case x := <-c1:
		return x, nil
	case nh := <-c2:
		return nil, nh
	}
	return nil, nil
}
func testMultiChannelSelect() {
	c1 := make(chan *Node, 1)
	x := &Node{}
	c1 <- x
	c2 := make(chan *nodeHolder, 1)
	nh := &nodeHolder{}
	c2 <- nh

	xp, nhp := multiSelect(c1, c2)
	assertSameAliases(x, xp)
	assertSameAliases(nh, nhp)
}

type DoAction interface {
	Action(*Node)
}

type DoerA struct {
	a *Node
}
type DoerB struct {
	a *Node
}

func (a *DoerA) Action(n *Node) {
	a.a = n
}
func (b *DoerB) Action(n *Node) {

}

func testInterfaces() {
	var doer DoAction = &DoerA{}
	if arbitrary() {
		doer = &DoerB{}
	}
	N := &Node{}
	doer.Action(N)
	if asB, ok := doer.(*DoerB); ok {
		assertSameAliases(nil, asB.a)
	}
	if asA, ok := doer.(*DoerA); ok {
		assertSameAliases(N, asA.a)
	}
}

func doActionOnArgument(d DoAction, n *Node) {
	d.Action(n)
}
func testInterfaces2() {
	var doer DoAction = &DoerA{}
	if arbitrary() {
		doer = &DoerB{}
	}
	N := &Node{}
	doActionOnArgument(doer, N)
	if asB, ok := doer.(*DoerB); ok {
		assertSameAliases(nil, asB.a)
	}
	if asA, ok := doer.(*DoerA); ok {
		assertSameAliases(N, asA.a)
	}
}

func testInterfaces3() {
	var doer DoAction = &DoerA{}
	if arbitrary() {
		doer = &DoerB{}
	}
	N := &Node{}
	doActionOnArgument(doer, N)
	// Same as above but don't use comma ok form of type cast
	if asB := doer.(*DoerB); asB != nil {
		assertSameAliases(nil, asB.a)
	}
	if asA := doer.(*DoerA); asA != nil {
		assertSameAliases(N, asA.a)
	}
}

type Document struct {
	name        awsString
	description awsString
	envVars     map[awsString]awsString
	commands    []awsString
	cwd         awsString
}

type str struct {
	v string
}
type awsString = *str

func sub(v awsString, params map[awsString]awsString) awsString {
	for p, arg := range params {
		if v.v == p.v {
			return arg
		}
	}
	return v
}
func SubstituteParams(d *Document, params map[awsString]awsString) {
	for env, value := range d.envVars {
		d.envVars[env] = sub(value, params)
	}
	for i := range d.commands {
		d.commands[i] = sub(d.commands[i], params)
	}
}
func testMockDocument() {
	d := &Document{&str{"test"}, &str{"test desc"}, map[awsString]awsString{}, []awsString{}, &str{"$HOME"}}
	SubstituteParams(d, map[awsString]awsString{})
}
