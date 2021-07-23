package main

type someInterface interface {
	doA() int
	doB() int
}

type type1 struct {
}

func (object *type1) doA() int {
	return 1
}

func (object *type1) doB() int {
	return 1
}

func doInvoke(instance someInterface) {
	go instance.doA()
	go instance.doB()
}

func main() {
	instance := someInterface(&type1{})
	doInvoke(instance)
}
