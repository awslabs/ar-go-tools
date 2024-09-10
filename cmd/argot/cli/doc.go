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

/*
Package cli implements the the Argot interactive CLI: a terminal application that lets you run most of the analyses
that are available in argot, with additional functionality to print verbose output and with commands to help you
understand, and possibly debug your analyses.

Usage:

	argot cli [flags] -config config-file.yaml [program files]

The flags are:

	-verbose=false
		verbose mode, overrides any verbose option specified in the config file
	-config config-file.yaml
		a configuration file for the analyses. The configuration file can be empty, but should always be specified.
		If [program files] is only one main.go file, the program will look for a file config.yaml in the same folder
		as the config file.

There are 29 commands you can use once you have started the argot-cli and your program has been loaded and some
information has been collected.

# Basic Commands

There are a few basic commands:

	help             print a list of the commands, with short help messages for each

	cd,ls            cd and ls allow you to change the working directory of the terminal and list its contents

	exit             exit exits the program gracefully

	state?           show a summary of the state, including path to config file and program

	stats            show some statistics about the current program

Commands that let you manipulate the state, reloading programs and configuration files:

	load  path       load a program, the path is the same type of argument you would pass to the argot-cli initially

	rebuild          reload the current program and rebuild it

	reconfig [path]  reload the config file, or load the config file at path if specified

# Inspecting Functions

Commands that let you inspect the functions in the program:

	list [name]        list all the functions matching name, or all loaded functions if no name is specified
	.                  Flag -r shows only reachable functions, and -s only summarized functions.

	where "name"	   show the locations of all the function matching name

	callees "name"     print the list of callees the functions matching name

	callers "name"     print the list of callers of the functions matching name

	showssa "name"     print the SSA form of the functions matching name

# Running Analyses

Commands to run analyses and inspect resulting information:

	summarize [name]    summarize all functions matching name, or every reachable function if no name is supplied

	summary "name"      print the summary of all functions matching name, if any

	buildgraph          builds the cross-cross function graph. You must first use `summarize` to build summaries

	taint               run the taint analysis

	trace               run a dataflow graph exploration (taint analysis from any node given its id)

	showdataflow        build and print the dataflow graph of a program

	showescape "name"   print the escape graph of all functions matching name

# Focused Mode

Commands to use in "focused" mode, which lets you focus on a particular function and obtained detailed information
about that function:

	focus "name"    	focus name focuses on a specific function and enters "focus" mode

	unfocus           	exit "focus" mode

	intra             	run the intra-procedural dataflow analysis and show its result.
	.                 	The -v flag shows intermediate results

	mayalias "value" 	show all the aliases of the values matching value

	ssaval "value"	 	show information about all the values matching value in the function

	ssainstr "instr" 	show information about all the instructions matching instr in the function

	pkg                 print the name of the focuse function's package

The commands showssa, summary and where can be used without an argument in focused mode, in which case the function
defaults to the currently focused function.
*/
package cli
