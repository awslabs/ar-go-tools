package main

func f1() {
	f2()
	f4()
	f3()
}

func f2() {
	f1()
}

func f3() {
	f2()
}

func f4() {
	f5()
}

func f5() {
	f1()
}

func g() {
	g1()
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

func main() {
	f1()
	g()
}
