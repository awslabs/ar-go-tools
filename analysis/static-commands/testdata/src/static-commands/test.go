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
	"context"
	"fmt"
	"os/exec"
)

func main() {
	exec.Command("ls")
	const ls = "ls"
	exec.Command(ls, "-l")
	exec.Command(ls, "-"+"l")
	exec.CommandContext(context.Background(), ls)

	cmd := "ls"
	exec.Command(cmd)                              // want "non-static os/exec.Command call"
	exec.Command(cmd + "")                         // want "non-static os/exec.Command call"
	exec.CommandContext(context.Background(), cmd) // want "non-static os/exec.Command call"

	fmt.Println("test")
}
