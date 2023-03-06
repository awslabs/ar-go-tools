package subpkg

type Data struct {
	Field string
}

type A interface {
	F() string
}

func (d Data) F() string {
	return d.Field
}

func (d Data) Sink(x string) {
	d.Field = x
}
