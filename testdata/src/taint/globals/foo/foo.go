package foo

var global any

func sink2(_ any) {
}

func SetGlobal(x any) {
	global = x
}

func CallSink() {
	sink2(global) // @Sink(ex5)
}
