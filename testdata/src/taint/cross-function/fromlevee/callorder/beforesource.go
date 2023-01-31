// This set of tests is borrowed from go-flow-levee

package callorder

import (
	"fromlevee/core"
)

// This type should *not* be identified as a Source.
type key struct {
	name string
}

func (k *key) Name() string {
	return k.name
}

func newKey() *key {
	return &key{
		name: "",
	}
}

func TestDoesNotReachSinkAfterSourceThroughValueCreatedBeforeSource() {
	// Taint should not propagate to this value.
	k := newKey()

	_ = map[string]string{"x": core.Source()}[k.name]

	core.Sink(k.Name())
}

func TestDoesNotReachSinkInIfBeforeSourceThroughValueCreatedBeforeSource() {
	// Taint should not propagate to this value.
	k := newKey()

	if true {
		core.Sink(k.Name())
	}

	_ = map[string]string{"x": core.Source()}[k.name]
}

func TestValueDeclaredBeforeSourceIsTainted() {
	var x interface{} = core.Innocuous()
	x = core.Source() // @Source(bs1)
	core.Sink(x)      // @Sink(bs1)
}

func TestSliceDeclaredBeforeSourceIsTainted() {
	xs := []interface{}{nil}
	xs[0] = core.Source() // @Source(bs2)
	core.Sink(xs)         // @Sink(bs2)
}

func TestAllBeforeSource() {
	TestDoesNotReachSinkAfterSourceThroughValueCreatedBeforeSource()
	TestDoesNotReachSinkInIfBeforeSourceThroughValueCreatedBeforeSource()
	TestValueDeclaredBeforeSourceIsTainted()
	TestSliceDeclaredBeforeSourceIsTainted()
}
