package main

func f1() { // node 2
	go f2()
	go f4()
	f3()
}

func f2() {
	f3()
}

func f3() {
	go f2()
}

func f4() {
	f5()
}

func f5() {
	go f4()
}

func g() {
	go g1()
	g2()
	g3()
}

func g1() {
	f1()
}

func g2() {
	g()
}

func g3() {
	g2()
}

func main() { // node 1
	go f1()
	g()
}
