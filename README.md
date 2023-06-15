[![build-analyze-test](https://github.com/awslabs/ar-go-tools/actions/workflows/bat.yml/badge.svg)](https://github.com/awslabs/ar-go-tools/actions/workflows/bat.yml)

# Argot

## Overview

Argot is a collection of tools:
- `taint` performs a taint analysis on a given program.
- `backtrace` identifies backwards data-flow traces from function calls
- `argot-cli` is a terminal-like interface for various part of the analysis (in `cmd/cli`)
- `compare` prints a comparison of the functions that are reachable according to two different analyses, and the
functions that appear in the binary,
- `dependencies` prints the dependencies of a given program,
- `maypanic` performs a may-panic analysis on a given program,
- `packagescan` scans imports in packages,
- `reachability` analyzes the program an prints the functions that are reachable within it,
- `render` can be used to render a graph representation of the callgraph, or to print the SSA form from the go analysis
package,
- `static-commands` identifies calls to command running executables with static arguments,
- `statistics` prints statistics about the program,


### Building the tools
The `Makefile` at the project root will call `go build` for each of the tools.

### Running the tools
For a more detailed guide on how to run and use the tools, see the [DESIGN.md](doc/DESIGN.md) document. There are links
to documents for each of the tools listed above, as well as an explanation on how to configure those tools that have
shared options.

## Source Code Organization

The executables are in the `cmd` folder, we have one executable per tool listed.

There is user documentation in the `doc` folder.

The test data is in the `testdata` folder. All the Go source files used in the tests are in `testdata/src`.

The library code, and most of the analysis implementations, is in the `analysis` folder. The main entry points are in
the `load_progam.go` file for loading progam and `analyzers.go` to call analyzers. The rest is organized in subfolders:
- `astfuncs` contains functions for manipulating the Go AST,
- `backtrace` implements the "backtrace" analysis,
- `concurrency` contains the concurrency analyses,
- `config` implements the config file system that is shared by all analyses,
- `dataflow` implements the dataflow analysis as well as the analysis state object, which is shared by many analyses.
Static analyses that required pointer and callgraph information should depend on the dataflow analysis state and use its
 functionality to build information about the SSA program.
- `defers` contains the defers analysis,
- `dependencies` contains the dependencies analysis,
- `lang` contains function for manipulating the Go SSA form (from the x/tools packages),
- `maypanic` contains the may-panic analysis,
- `reachability` contains function-reachability analyses
- `refactor` contains implements refactoring operations,
- `render` contains various information rendering utilities
- `static-commands` implements the static command detection analysis,
- `summaries` defines dataflow summaries of some functions,
- `taint` implements the taint analysis

The `internal` folder also contains code that implements utility functions used through the analysis code.