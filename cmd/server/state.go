package main

// serverState stores state information about the terminal. Not used to store information about the program
// being analyzed
type serverState struct {
	// the current working directory
	Wd string
}

var state = serverState{}
