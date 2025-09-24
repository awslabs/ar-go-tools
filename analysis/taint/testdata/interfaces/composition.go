package main

type Reader interface {
	Read() string
}

type Writer interface {
	Write(string)
}

type ReadWriter interface {
	Reader
	Writer
}

type Closer interface {
	Close()
}

type ReadWriteCloser interface {
	ReadWriter
	Closer
}

type DataProcessor struct {
	data string
}

func (d *DataProcessor) Read() string {
	return d.data
}

func (d *DataProcessor) Write(s string) {
	d.data = s
}

func (d *DataProcessor) Close() {
	d.data = ""
}

func processReader(r Reader) {
	sink(r.Read()) // @Sink(composition1)
}

func processReadWriter(rw ReadWriter) {
	data := rw.Read()
	rw.Write("processed")
	sink(data) // @Sink(composition1)
}

func processReadWriteCloser(rwc ReadWriteCloser) {
	data := rwc.Read()
	rwc.Close()
	sink(data) // @Sink(composition1)
}

func testComposition() {
	processor := &DataProcessor{data: source()} // @Source(composition1)

	// Test taint flow through composed interfaces
	processReader(processor) // should reach sink
	processReadWriter(processor)
	processReadWriteCloser(processor)
}
