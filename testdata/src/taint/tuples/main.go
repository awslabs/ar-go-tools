package main

func source() string {
	return "tainted-data"
}

func sink(_ any) {}

func main() {
	TestTuple1()
}

func TestTuple1() {
	x, y := F(source()) // @Source(t1)
	sink(x)             // @Sink(t1)
	sink(y)             // this should be ok @Sink(t1)
}

func F(a string) (string, string) {
	return a + "ok", "fresh"
}
