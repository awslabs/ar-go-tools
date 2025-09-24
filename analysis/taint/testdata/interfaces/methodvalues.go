package main

type Container struct {
	value string
}

func (c Container) GetValue() string {

	// Method on value
	return c.value
}

func (c *Container) SetValue(s string) {
	// Method on pointer
	// Bad code practice, but it's for testing
	c.value = s
}

func (c Container) ProcessAndSink() {
	// Method on value
	sink(c.value) // @Sink(methodvalue1)
}

type Processor interface {
	Process() string
}

func (c Container) Process() string {
	return c.value
}

func testMethodValues() {
	tainted := Container{value: source()} // @Source(methodvalue1)
	clean := Container{value: "clean"}

	// Method value from instance
	getValue := tainted.GetValue
	sink(getValue()) // @Sink(methodvalue1)

	// Method value from type
	processFunc := Container.ProcessAndSink
	processFunc(tainted) // should reach sink inside method
	processFunc(clean)   // should not reach sink inside method

	// Method value with interface
	var processor Processor = Container{value: source()} // @Source(methodvalue3)
	processMethod := processor.Process
	// Use method's value and call it, still propagates taint
	sink(processMethod()) // @Sink(methodvalue3)

	// Pointer method value
	container := &Container{}
	setValue := container.SetValue
	// Use method's value to taint the data, still propagates taint
	setValue(source())    // @Source(methodvalue4)
	sink(container.value) // @Sink(methodvalue4)
}
