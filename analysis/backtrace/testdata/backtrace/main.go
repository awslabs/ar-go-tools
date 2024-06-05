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
	"os"
	"os/exec"
)

var global = "ls"

func main() {
	cmd := exec.Command("ls")
	if err := cmd.Run(); err != nil {
		panic(err)
	}

	cmd1 := exec.Command(os.Args[0], os.Args[1:]...)
	if err := cmd1.Run(); err != nil {
		panic(err)
	}

	if err := runcmd("ls1"); err != nil {
		panic(err)
	}
	if err := runcmd("ls2"); err != nil {
		panic(err)
	}

	if err := runcmd(os.Args[0], os.Args[1:]...); err != nil {
		panic(err)
	}

	foo()

	runcmd(bar("ls3"))

	runglobal()
}

func foo() {
	if err := runcmd("ls4"); err != nil {
		panic(err)
	}

	x := bar("x")
	fmt.Println(x)
}

func bar(x string) string {
	return baz(x)
}

func baz(x string) string {
	return x
}

func runcmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run command: %v", err)
	}

	return nil
}

func runglobal() {
	global = baz("hello1")
	runcmd(write())
}

func write() string {
	if global != os.Args[0] {
		global = baz("hello2")
	}
	return global
}
