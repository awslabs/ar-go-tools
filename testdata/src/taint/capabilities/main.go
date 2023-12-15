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

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"

	"capabilities/extern"
)

func main() {
	example1()
	example2()
}

// example1 listens for incoming connections and writes the contents to a file.
func example1() {
	f, err := os.Create("customer-data")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	handleConn := func(c net.Conn) {
		writeCustomerData(c, f)
	}
	listen(handleConn)
}

func listen(handleConn func(net.Conn)) {
	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := net.Listen("tcp", ":2000") // @Source(Listen)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept() // @Source(Accept)
		if err != nil {
			panic(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			// Echo all incoming data.
			if _, err := io.Copy(c, c); err != nil {
				return
			}

			handleConn(c)

			// Shut down the connection.
			if err := c.Close(); err != nil {
				return
			}
		}(conn)
	}
}

func writeCustomerData(conn net.Conn, w io.Writer) {
	b := make([]byte, 50)
	if _, err := conn.Read(b); err != nil {
		panic(fmt.Errorf("failed to read connection: %v", err))
	}

	// Source(Write) is a false-positive because net.Conn implements the io.Writer interface which gives it the
	// CAPABILITY_NETWORK capability.
	if _, err := w.Write(b); err != nil { // @Source(Write) // @Sink(Listen, Accept, Write)
		panic(fmt.Errorf("failed to write customer data: %v", err))
	}
}

// example2 tests using a context to make sure any calls to a function with the specified capability
// in the extern package are not counted as sources or sinks.
func example2() {
	data := runtime.GOROOT()   // @Source(rt)
	extern.Echo(data)          // safe because context is package capabilities/extern
	exec.Command("echo", data) // @Sink(rt)
}
