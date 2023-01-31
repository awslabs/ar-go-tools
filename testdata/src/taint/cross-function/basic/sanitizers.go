package main

func Sanitize(x string) string {
	return x
}

func gen(s *string) {
	*s = source1() // @Source(se1)
}

func sanitizerExample1() {
	s := "ok"
	gen(&s)
	sink1(Sanitize(s))
}

func runSanitizerExamples() {
	sanitizerExample1()
}
