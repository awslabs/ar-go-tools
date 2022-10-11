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
