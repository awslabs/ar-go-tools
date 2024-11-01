
# Dependency Scanner

The dependency analysis tool ('dependencies') is a whole program analysis tool that performs a conservative reachability analysis to measure what fraction of each imported library is (or at least could be) used by the program.  

The purpose of this tool is to get a sense of how much of each dependency is actually consumed.  So, for example, you might discover that a fairly large package is being imported but only a handful of functions are actually needed.   While importing packages for a single function is considered idiomatic in other languages, Go encourages minimizing the number of dependencies. With the `-usage` and `-loc` options, you control when a warning appears: if a module is used less than `-usage`% (default 10%) *and* less than `-loc` lines of SSA then a warning is printed on the output.

For example, the tool may print an output as follows:
```shell
Reading sources
[INFO]  Loaded 0 annotations from program
[INFO]  Analyzing
[INFO]  allFunctions contains 17911 total
[INFO]  findEntryPoints found 26 entry points
[INFO]  FindReachable reports 10991 reachable functions
[INFO]  Dependencies (direct or indirect, name, reachable LOC, total LOC, % LOC usage):
[INFO]   direct  github.com/awslabs/ar-go-tools   68954  72438  (95.2 %)
[INFO]   direct  github.com/dave/dst              101    31016  (0.3 %)
[INFO]   direct  github.com/google/shlex          296    314    (94.3 %)
[WARN]   direct  github.com/yourbasic/graph       7      2455   (0.3 %)  <- less than 100 lines used, and below 10.0 % usage
[INFO]   direct  golang.org/x/exp                 1306   2591   (50.4 %)
[INFO]   direct  golang.org/x/sys                 1122   6887   (16.3 %)
[INFO]   direct  golang.org/x/term                1709   2018   (84.7 %)
[INFO]   direct  golang.org/x/tools               167944 185822 (90.4 %)
[WARN]   direct  gonum.org/v1/gonum               5      989    (0.5 %)  <- less than 100 lines used, and below 10.0 % usage
[INFO]  indirect golang.org/x/mod                 6      555    (1.1 %)
[INFO]  indirect golang.org/x/sync                89     184    (48.4 %)

``` 
Indicating that the dependencies `gonum.org/v1/gonum` and `github.com/yourbasic/graph` should possibly be eliminated (we eliminated those from our code).

The dependency tool can also be useful in discovering when a dependency is inadvertently being linked into a program where it should not be.  For example, if test libraries are reachable from production code.  In a codebase with multiple executables, the dependency tool can help detect when a change to a shared package results in additional code being imported into executables where it is not required.  

The dependency tool measures the size of functions by counting the SSA instructions in each function. It presents the results as a ratio of the number of instructions in a package that are reachable within a program to the total number of instructions in the package.  While SSA instructions do not correspond directly to lines of code, they are a reasonable proportional estimate of the size of different dependencies and the fraction of the dependency actually consumed.  The dependency tool does not measure the size of data or constants that might be imported, only functions, and will be less accurate with packages that exist primarily to import data rather than code.

### Generate coverage data
If invoked with the `-cover` option, the dependency tool will generate an output file using the Go test coverage format to indicate exactly which lines in the codebase are reachable (covered) and which are not (uncovered).  This coverage file can then be interactively browsed using the "go tool cover" command.  It can also be merged with other coverage files using tools such as github.com/wadey/gocovmerge.  So, for example, if your codebase consists of multiple executables, you can run the dependency tool on each binary and then merge the coverage results to see how much each dependency is needed across the set of executables.  Similarly, if you cross-compile your code, you can run the dependency tool with each different platform (e.g. GOOS=windows, GOOS=linux, GOOS=darwin) and merge the coverage results to observe how much each dependency is needed across all target systems.


### Build options and including tests

The dependency tool allows the buildmode and tags to be controlled with command line arguments, as per all the other AR-Go-tools.  [cf: common docs].  This may be deprecated.
The `-with-tests` flags instructs it to include all the test files when computing the dependency usage. By default, tests are excluded.
The dependency tool supports a `-stdlib` flag to instruct it to suppress output of standard library packages and focus entirely on third-party dependencies.



### Generate a dependency graph

If invoked with the `-graph` option, the dependency tool will generate a directed graph of which packages depend on other packages.  It will emit a sorted list of packages as standard output, and emit a graphviz-compatible file format with the complete output.  This can be quite large and too much for graphviz to render, but searching the file for specific package names will provide useful data about how a particular package is being imported.  This is similar to the "go mod why" function, but that will show you every potential dependency of every package, whereas this tool will limit its output to only those dependencies that are actually used in the program being analyzed. 

### Generate CSV

The tool can generate a CSV summarizing the results with the `-csv <output-file-name>` option. Each line will be of the form:
```
dependency name, is direct dependency?, reachable LoC, total LoC, usage percentage
```
Users can consume this information instead of the terminal output.

## All Options
The `dependency` tool accepts the following options:
- `-help` prints a list of options.
- `-config <filename>` allows the user to specify a config file (see [intro doc](./00_intro.md)). The options used are the `log-level` option and the `pkg-filter` option, which in this application controls for which packages some additional debug statements are printed.
- `-cover <filename>` instructs the dependencies tool to print coverage information in `<filename>`.
- `-graph <filename>` instructs the tool to output a dependency graph in the `<filename>` file.
- `-csv <filename>` instructs the tool to print a summary of the dependencies and their usage ratio in `<filename>`.
- `-stdlib` instructs the tool to suppress output of standard library packages (see details above)
- `-usage` sets a threshold usage percentage under which a dependency's usage is reported with a warning (by default, 10%).
- `-loc` sets the absolute number lines of code used below which a warning is reported (by default, 100).
- `-with-test` sets the test inclusion to true. By default, tests are not included when measuring dependency usage. 
