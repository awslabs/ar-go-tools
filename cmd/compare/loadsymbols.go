package main

import (
	"bufio"
	"os"
	"strings"
)

// ReadNMFile reads a file produced from the executable binary using
// go tool nm > filename
// todo: figure out how to execute nm directly and scarf the stdout
// todo: link https://pkg.go.dev/cmd/internal/objfile@go1.19.3 and
// process the symbol structs directly
func ReadNMFile(filename string) (map[string]bool, error) {
	symbols := make(map[string]bool)
	infile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	fileScanner := bufio.NewScanner(infile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		entry := strings.Split(fileScanner.Text(), " ")
		if len(entry) != 4 || entry[2] != "T" {
			//fmt.Fprintln(os.Stderr, len(entry), entry)
			continue
		}

		name := entry[3]
		// if the name contains an embedded (*, move it to the start of the string
		// to match the name formatting used by the ssa package.
		index := strings.Index(name, "(*")
		if index > 0 {
			name = "(*" + name[:index] + name[index+2:]
			//fmt.Fprintf(os.Stderr, "Munged name is %s\n", name)
		}
		symbols[name] = true
	}

	infile.Close()

	return symbols, nil
}
