package main

import "fmt"

type A interface {
	error
	Code() string
	Message() string
	OrigErr() error
}

type B interface {
	Out() string
}

// C implementation

type C struct {
	CData   string
	message string
}

func (c C) Out() string {
	return "Output-" + c.message
}

func (c C) OrigErr() error {
	return fmt.Errorf("err:%s", c.CData)
}

func (c C) Error() string {
	return fmt.Sprintf("error: %s", c.CData)
}

func (c C) Code() string {
	return "231"
}

func (c C) Message() string {
	return c.message
}

func (c C) String() string {
	return c.CData + c.message
}

// E implementation

type E struct {
	Data    string
	message string
}

func (e *E) OrigErr() error {
	return fmt.Errorf("err:%s", e.Data)
}

func (e *E) Error() string {
	return fmt.Sprintf("error: %s", e.Data)
}

func (e *E) Code() string {
	return "231"
}

func (e *E) Message() string {
	return e.message
}

func (e *E) String() string {
	return e.Data
}

// D implementation

type D struct {
	Data    string
	Storage string
}

func (d D) OrigErr() error {
	return fmt.Errorf("err:%s", d.Data)
}

func (d D) Error() string {
	return fmt.Sprintf("error: %s", d.Data)
}

func (d D) Code() string {
	return "123" + d.Storage
}

func (d D) Message() string {
	return d.Storage
}

func (d D) String() string {
	return d.Data
}

// ===

type X struct {
	r interface{}
}

func (x X) Out() string {
	return "x"
}

// ===

func (x X) HasLen() (int, bool) {
	type lenner interface {
		Len() int
	}

	if lr, ok := x.r.(lenner); ok {
		return lr.Len(), true
	}

	return 0, false
}

// ===

func transmitMessageWithErr(a A) string {
	return a.Message() + a.Code()
}

func callCode(a A) string {
	return a.Code()
}

func callOut(b B) string {
	return b.Out()
}

func example1() {
	tainted := source() // @Source(example1)
	e := &E{}
	d := &D{}
	c := &C{}
	x := X{r: tainted}
	e.message = tainted
	e.Data = "a" + c.Out()
	c.CData = e.Data + e.message
	if _, ok := x.HasLen(); ok {
		sink(callCode(c))
	}
	sink(e.Code())
	sink(transmitMessageWithErr(e) + transmitMessageWithErr(d) + transmitMessageWithErr(c)) // @Sink(example1)
	sink(callOut(c))                                                                        // @Sink(example1)
}

func main() {
	example1()
}
