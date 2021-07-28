package main

type innerInterface interface {
	doA() int
	doB() int
}

type someInterfaceGroup interface {
        innerInterface
}

type type1 struct {
}

// used by someInterface
func (object *type1) doA() int {
	return 1
}

// used by someInterface
func (object *type1) doB() int {
	return 2
}

// NOT used by someInterface
func (object *type1) doC() int {
	return 3
}

func doInvoke(instance someInterfaceGroup) {
	go instance.doA()
	go instance.doB()
}

func main() {
	instance := someInterfaceGroup(&type1{})
	doInvoke(instance)
}
