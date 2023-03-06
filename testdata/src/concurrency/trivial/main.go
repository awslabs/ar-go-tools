package main

func main() {
	go f1()
	go f2()
}

func f1() {
	f11()
}

func f11() {
	go f12()
	go f13()
}

func f12() {
}

func f13() {

}

func f2() {
	go f12()
	go f12()
	f13()
}
