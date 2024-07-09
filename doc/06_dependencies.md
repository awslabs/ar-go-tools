
# Dependency Scanner

The dependency analysis tool ('dependencies') is a whole program analysis tool that performs a conservative reachability analysis to measure what fraction of each imported library is (or at least could be) used by the program.  

The purpose of this tool is to get a sense of how much of each dependency is actually consumed.  So, for example, you might discover that a fairly large package is being imported but only a handful of functions are actually needed.   While importing packages for a single function is considered idiomatic in other languages, Go encourages minimizing the number of dependencies.

The dependency tool can also be useful in discovering when a dependency is inadvertently being linked into a program where it should not be.  For example, if test libraries are reachable from production code.  In a codebase with multiple executables, the dependency tool can help detect when a change to a shared package results in additional code being imported into executables where it is not required.  

The dependency tool measures the size of functions by counting the SSA instructions in each function.  It presents the results as a ratio of the number of instructions in a package that are reachable within a program to the total number of instructions in the package.  While SSA instructions do not correspond directly to lines of code, they are a reasonable proportional estimate of the size of different dependencies and the fraction of the dependency actually consumed.  The dependency tool does not measure the size of data or constants that might be imported, only functions, and will be less accurate with packages that exist primarily to import data rather than code.

If invoked with the -cover option, the dependency tool will generate an output file using the Go test coverage format to indicate exactly which lines in the codebase are reachable (covered) and which are not (uncovered).  This coverage file can then be interactively browsed using the "go tool cover" command.  It can also be merged with other coverage files using tools such as github.com/wadey/gocovmerge.  So, for example, if your codebase consists of multiple executables, you can run the dependency tool on each binary and then merge the coverage results to see how much each dependency is needed across the set of executables.  Similarly, if you cross-compile your code, you can run the dependency tool with each different platform (e.g. GOOS=windows, GOOS=linux, GOOS=darwin) and merge the coverage results to observe how much each dependency is needed across all target systems.

The dependency tool supports a `stdlib` flag to instruct it to suppress output of standard library packages and focus entirely on third-party dependencies.  [todo: should we standardize on these filtering functions, and differentiate between the program itself (identified in go.mod), stdlib, extended stdlib, x/tools, and true third-party?  If so, cf common docs.]

The dependency tool allows the buildmode and tags to be controlled with command line arguments, as per all the other AR-Go-tools.  [cf: common docs].  This may be deprecated.

If invoked with the -graph option, the dependency tool will generate a directed graph of which packages depend on other packages.  It will emit a sorted list of packages as standard output, and emit a graphviz-compatible file format with the complete output.  This can be quite large and too much for graphviz to render, but searching the file for specific package names will provide useful data about how a particular package is being imported.  This is similar to the "go mod why" function, but that will show you every potential dependency of every package, whereas this tool will limit its output to only those dependencies that are actually used in the program being analyzed. 

## Options
The `dependency` tool accepts the following options:
- `-help` prints a list of options.
- `-config <filename>` allows the user to specify a config file (see [intro doc](./00_intro.md)). The options used are the `log-level` option and the `pkg-filter` option, which in this application controls for which packages some additional debug statements are printed.
- `-cover <filename>` instructs the dependencies tool to print coverage information in `<filename>`.
- `-graph <filename>` instructs the tool to output a dependency graph in the `<filename>` file.
- `-csv <filename>` instructs the tool to print a summary of the dependencies and their usage ratio in `<filename>`.
- `-stdlib` instructs the tool to suppress output of standard library packages (see details above)
- `-usage` sets a threshold usage percentage under which a dependency's usage is reported with a warning (by default, 10%).