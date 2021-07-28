package main

type someInterface interface {
	doA() int
	doB() int
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

func doInvoke(instance someInterface) {
	go instance.doA()
	go instance.doB()
}

func main() {
	instance := someInterface(&type1{})
	doInvoke(instance)
}
