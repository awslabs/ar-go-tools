// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
