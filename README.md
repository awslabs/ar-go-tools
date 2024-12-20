[![build-analyze-test](https://github.com/awslabs/ar-go-tools/actions/workflows/bat.yml/badge.svg)](https://github.com/awslabs/ar-go-tools/actions/workflows/bat.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Argot


## Overview

Argot is a collection of static analysis tools:
- `taint` performs a taint analysis on a given program
- `backtrace` identifies backwards data-flow traces from function calls
- `cli` is an interactive terminal-like interface for parts of the analysis (in `cmd/cli`)
- `syntactic` runs syntactic analyses
- `compare` prints a comparison of the functions that are reachable according to two different analyses, and the
functions that appear in the binary
- `dependencies` prints the dependencies of a given program
- `maypanic` performs a may-panic analysis on a given program
- `packagescan` scans imports in packages
- `reachability` analyzes the program an prints the functions that are reachable within it
- `render` can be used to render a graph representation of the callgraph, or to print the SSA form from the go analysis
package
- `ssa-statistics` prints statistics about the program

All of these tools are sub-commands of the `argot` command.

### Building the tools
The `Makefile` at the project root has commands to build Argot.

Run `make argot-build` to only compile the `argot` binary.

Run `make argot-install` to install `argot` via the `go install` command.

Run `make release` to run all the linters and tests.

### Running the tools
For a more detailed guide on how to run and use the tools, see the [00_intro.md](doc/00_intro.md) document. There are links
to documents for each of the tools listed above, as well as an explanation on how to configure those tools that have
shared options.

## Source Code Organization

The executables are in the `cmd` folder. There are currently only two: `argot` and `racerg` (an experimental static data race detector).

There is user documentation in the `doc` folder.

The library code, and most of the analysis implementations, is in the `analysis` folder. The main entry points are in
the `load_program.go` file for loading the program and `analyzers.go` to call the analyzers. The rest is organized in subfolders:
- `astfuncs` contains functions for manipulating the Go AST,
- `backtrace` implements the "backtrace" analysis,
- `concurrency` contains the concurrency analyses,
- `config` implements the config file system that is shared by all analyses,
- `dataflow` implements the dataflow analysis as well as the analysis state object, which is shared by many analyses.
Static analyses that require pointer and callgraph information should depend on the dataflow analysis state and use its
 functionality to build information about the SSA program.
- `defers` contains the defers analysis,
- `dependencies` contains the dependencies analysis,
- `lang` contains function for manipulating the Go SSA form (from the x/tools packages),
- `loadprogram` contains utilities to load a program with its SSA representation and the annotations of the program,
- `maypanic` contains the may-panic analysis,
- `ptr` contains utilities to build an analysis state with the pointer analysis result,
- `reachability` contains function-reachability analyses,
- `refactor` contains implements refactoring operations,
- `render` contains various information rendering utilities
- `summaries` defines dataflow summaries of some functions,
- `taint` implements the taint analysis

The test data for the analyses are in individual `analysis/___/testdata` folders. 

The `internal` folder also contains code that implements utility functions used through the analysis code.
