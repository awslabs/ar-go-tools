# Argot CLI

The command line tool `argot-cli` (the CLI) provides many commands to help programmers understand the analyses performed by other tools in Argot. In order to use the CLI effectively, you should have a high-level understanding of static analysis techniques. You should have an understanding of what the SSA reprsentation of a program is to use the SSA related tools, and an understanding of dataflow analysis techniques in order to use the dataflow related tools.

Like many of the tools there,
it must start with a program to analyze and a configuration file. To start the `argot-cli` with some program `main.go` and some configuration file `config.yaml`:
```
argot-cli -config config.yaml main.go
```
> If you installed the CLI using `make install`, then call `argot-cli`. If you only built the cli using `make argot-cli`, look for the executable `./bin/argot-cli`

We will illustrate all the features of the CLI through an example in this document. For a complete list of the commands available in the CLI, type `help` once the program has started an the prompt starting with `>` appears. Type `exit` in the prompt to exit the CLI.
You can also have a look at [the documentation](../cmd/argot-cli/doc.go) of the executable.




# Argot CLI Configuration






# Detailed Example: Loading `testdata/src/taint/example1`

First, we use the CLI to load the Go program in `testdata/src/taint/example1`:
```[shell]
argot-cli -config ./testdata/src/taint/example1/config.yaml ./Testdata/Src/Taint/Example1/Main.Go
```
> 📝 If the program is only a `main.go` file and there is a file `config.yaml` in the same directory, then you can omit the `-config ...`. In the example above, using `argot-cli ./testdata/src/taint/example1/main.go` will load the same program with the same configuration.

You should see first a few lines of output that explain what the tool is analyzing. First, a `Reading sources` message will indicate that the tool is reading the sources. It should be followed by messages similar to the following:
```
2023/05/24 14:19:22 Gathering global variable declaration in the program...
2023/05/24 14:19:22 Gathering values and starting pointer analysis...
2023/05/24 14:19:22 Computing information about types and functions for analysis...
```
With matching messages that indicate each of the analyses (pointer analysis, global variable collection, type and function collection) terminate. Finally, the tool looks where variables are bound by some closure in the code.
```
2023/05/24 14:19:22 Gathering information about pointer binding in closures
```
All the analyses should take less than a second in total for this simple example, but for larger programs, it can takes minutes!
If everything runs successfully you should be presented with a prompt:
```
2023/05/24 14:19:22 Pointer binding analysis terminated, added 0 items (0.00 s)
>
```
And you can start querying and rendering the state of the analyses, as well as run other analyses.


## First Steps: State, Statistics and Utilities

First, let us have a look at a few commands that let you inspect the current state of the tool and change some basic information about it.

The [`state?`](#state) command print information about the current state of the tool, including the path to the program it is analyzing, the path to the configuration file and the working directory.
In our example:
```
> state?
Program path      : ./testdata/src/taint/example1/main.go
Config path       : ./testdata/src/taint/example1/config.yaml
Working dir       : <somedir>
Focused function  : none
# functions       : 5467
# summaries built : 0
flow graph built? : false
```
We will see later how to *focus* on a specific function. `state?` also prints the number of functions in the loaded program, the number of dataflow summaries that have been built and whether the inter-procedural dataflow graph has been built. The last two parts are specific to the dataflow-based analyeses, such as the [taint analysis](taint.md) and the [backwards flow analysis](TODO).


### Utilities
The tool provides a few utilities to change directories, reload config files and programs:
- You can reload the configuration from disk at any point by using the [`reconfig`](#reconfig) command. It optionally accepts an argument that is a path to a new configuration file.
- You can rebuild the program using [`rebuild`](#rebuild) or load a new program using [`load`](#load). This allows you to modify the source code of the program you are analyzing and reload it without leaving the CLI.
- The [`ls`](#ls) command lists directories and files in the current working directory.
- If you want to change the working directory, use the [`cd`](#cd) command, for example:
```
> cd testdata/src/taint/example1
```
If you have changed directory and need to reload the config file or the program, you will need to respecify the paths, for example `> reconfig config.yaml` in this case to reload the config file. Calling `> rebuild` would fail here, so you need to first load the program relatively to the new location by using `> load main.go` (and any subsequent call to `> rebuild` will succeed, provided the program can be compiled and you have not changed location).


### Statistics

When the tool loads a program, it computes a [Static Single Assignment (SSA)](https://en.wikipedia.org/wiki/Static_single-assignment_form) representation of the program.
The `stats` command prints general statistics about the SSA program that has been loaded.
In its simplest usage, `stats` prints how many functions, instructions and blocks there are in the program:
```
> stats
SSA stats:
 # functions                   5467
 # nonempty functions          4945
 # blocks                      29739
 # instructions                190921
```
Additionally, `stats` has a few *subcommands*: `help`, `all`, `general` and `closures`. `stats help` prints a help message that explains those options.  The `general` statistics are the ones printed by the command withtout subcommands. `stats closures` prints more information about closure usage and number of closures in the code. For the `closure` subcommand, several filters can be used to print locations of closure usage.
To print all information, type:
```
> stats all -U -C -I
```
In our example, there is only a few closures and this reports only two anonymous functions capturing channels.
> 📝 Command flags such as `-U`, `-C` and `-I` above always need to be specified separately with their preceding dash. Commands like `stats` can also accept arguments like `--filter something`


## Inspecting The SSA

The CLI provides a number of commands to inspect the SSA representation of the code, as well as the results of the pointer analysis.
An entry point to looking more precisely at those function is to use the [`list`](#list) command, which lists all the functions in the program, possibly with some filters.
The arguments provided to the commands are interpreted as regexes, and used as filters on the output. For example, the functions in the `main` package of the program are loaded in the `command-line-arguments` package. You can list them using:
```
> list command-line-arguments.*
```
Alternatively, using a shorter regex in `list com.*ts.` would work as well in this case. Note that in terminals that support escape codes, some functions might appear in different colors with different markers dependening on whether they are reachable and/or summarized. The markers before the function name indicate whether a function is summarized `[x][_]` or reachable `[_][x]` or both `[x][x]`. Initially, you should see an ouput of the form:
```
> list com.*ts
Found 10 matching functions:
[summarized?][reachable?] function name
[_][x] command-line-arguments.f
[_][x] command-line-arguments.g
[_][x] (command-line-arguments.fooProducer).source
[_][x] command-line-arguments.sink
[_][x] command-line-arguments.init
[_][x] command-line-arguments.main
[_][x] command-line-arguments.test2
[_][x] command-line-arguments.fetchAndPut
[_][x] command-line-arguments.h
[_][_] (*command-line-arguments.fooProducer).source
```
Indicating all but one function are reachable, and none are summarized. You can print only reachable functions using the `-r` flag and only summarized functions using the `-s` flag.

Now let us look closer at the `test2` function in `main.go`.

First, we can get its location by using the [`where`](#where) command:
```
> where test2
Location: /<somedir>/testdata/src/taint/example1/main.go:64:6
```
will print the location of `test2`. The argument is interpreted as a regex, and the location of any function whose name matches the regex will be printed.


To show the SSA representation of a function, use the [`showssa`](#showssa) command. For example, the command:
```
> showssa test2
```
Will print the SSA representation of the `test2` function. The argument provided to `showssa` is interpreted as a regex; any function matching that regex will be printed in the terminal. For more information about the representation, look at the [ssa package](https://pkg.go.dev/golang.org/x/tools/go/ssa#section-documentation).


### Callers and Callees
The [`callers`](#callers) and [`callees`](#callees) commands allow the user to look at the information contained in the [call graph](https://en.wikipedia.org/wiki/Call_graph).
For example, `> callers test2` will print all the functions calling the functions whose name match `test2` and `> callees test2` will print the functions called by the functions matching `test2`. For each caller/callee site, the output will contain:
- the SSA instruction of the call.
- the position in the source file.
- the full name of the function being called (`callees`), or the full name of the caller (`callers`).
For example:
```
> callers test2
Callers of command-line-arguments.test2:
        At SSA instruction test2():
         - position: /<somedir>/testdata/src/taint/example1/main.go:59:7
         - command-line-arguments.main
```
Indicates that `test2` is called by `main` in a call instruction `test2()` at the given position.


## Using Focused Mode

When starting the CLI, the default is that all functions are in scope. The `list` and `showssa` commands are useful to get an idea of what functions are loaded, and what is the SSA representation of those functions. In order to get more detailed information about the content of a specific function, this function needs to be *focused*.

To focus on a specific function, give an argument to the [`focus`](#focus) command:
```
> focus test2
Focusing on command-line-arguments.test2.
```
The CLI prints a response that shows is has succsefully loaded the function. The prompt should now be prefixed by the name of the function.

> ⚠  The argument of focus is interpreted as a regex (as in most cases in the CLI) but only one function must match that regex. For example, if the focus command is called with `test` as argument in the example, you should see an error output that says <font color='red'>Too many matching functions:</font> and then list all the matches. The list of matches should help you refine your regex to match only the function you want. If no function matches the regex, for example if you use the command `focus doesnotexist`, then an error <font color='red'>No matching function.</font> should be printed.

When a function is focused, typing `where` without argument shows the location of the focused function:
```
test2 > where
Location: <somedir>/testdata/src/taint/example1/main.go:64:6
```
Similarly, you can use `showssa` without any argument:
```
test2 > showsssa
....
```
In addition to the commands seen previously, some additional commands are available in focused mode.
- [`ssaval`](#ssaval) shows all the SSA values matching the regex provided as argument, in the focused function. It will also print information showing the type of the value, the kind of SSA value, its location and the instruction defining it. It will also print aliasing information that has been computed during the pointer analysis. For example:
```
test2 > ssaval t0
Matching value: t0
      kind    : *ssa.Alloc
      type    : *command-line-arguments.fooProducer
      instr   : local fooProducer (w)
      location: /<somedir>/testdata/src/taint/example1/main.go:65:2
  referrers:
    [&t0.I [#0]]   [*t0]
  direct aliases:
    [t0 (local fooProducer (w))]
```
The output of the command shows that exactly one value matches the name `t0`; it is an allocation (the kind is `*ssa.Alloc`) of a variable of type `*command-line-arguments.fooProducer`. The instruction also indicates that this is a local variable, since it is defined by the instruction `local fooProducer (w)`. Recall that the SSA representation is defined in the [ssa package](https://pkg.go.dev/golang.org/x/tools/go/ssa).
The instructions that refer to the value `t0` are then displayed: an instruction that takes the adress of field `I` of `t0`, and a dereference of `t0` itself. To inspect those instructions, one can use the next command `ssainstr` or look at the ssa (using `showssa`) to see which value it defines.
The final element in the output shows that the only direct alias of `t0` is itself.


- [`ssainstr`](#ssainstr) shows all the SSA instructions matching the regex provided as argumnet in the focused function. For example, `test2 > ssainstr t1` should print the only instruction that refers to `t1` in the SSA. The matching location in the source code is the location where the struct field is set to 1.
- [`pkg`](#pkg) shows the package of the current function.

At any point, you can exit *focused* mode by using the ['unfocus'](#unfocus) command:
```
test2 > unfocus
Unfocus test2.
```

## Running Dataflow Analyses

The first step that should be taken in order to run dataflow analyses is to built the dataflow summaries of the functions of interest in the program. The [`summarize`](#summarize) command does exactly that: it builds the summaries for all functions of interest, according to the config file, when no argument is specified. If some argument regex is specified, then it builds the summaries for only the functions matching the regex. For more information on what parts of the configuration file are relevant, refer to the guide on using the [taint analysis](taint.md) tool.

For example, you can summarize the `test2` function:
```
> summarize test2
Running single-function analysis on functions matching test2
1 summaries created, 1 built.
```
Then, if you call `> list test2` you should observe that the function is summarized, witnessed by the line `[x][x] command-line-arguments.test2` in the output. Summaries can be inspected using the [`summary`](#summary) command.
In this example:
```
> summary test2
Found summary of command-line-arguments.test2:
Summary of test2:
  Call "[#461.0] (SA)call: (fooProducer).source(t3) in test2":
    (#0) -> "[#461.3] @arg 0:t5 in [#461.2] (SA)call: f(t5, "ok":string) in test2 "
  Call "[#461.2] (SA)call: f(t5, "ok":string) in test2":
    (#0) -> "[#461.6] @arg 0:t6 in [#461.5] (SA)call: sink(t6) in test2 "
(1 matching summaries)
```
Shows that there are two dataflow edges in the dataflow summary of `test2`. The first edge indicates that the result of the call to `(fooProducer).source` flows to the argument `t5` (at position 0) in the call to `f`. The second edge indicates that the result of the call to `f` flows to the argument `t6` (also at position 0) in the call to `sink`.

To summarize all functions, call `> summarize`. 12 summaries should have been built by this step. This step is an *intra-procedural* analysis step: every function is analyzed individually, without consideration of the other functions. To perform a full program analysis, we need to link those summaries together.

The [`buildgraph`](#buildgraph) command builds *inter-procedural* edges between the summaries; it links function calls in one summary to the summary of the function being called. As such, it makes sense to run `buildgraph` only after you have run `summarize`. Running `> buidlgraph` does not produce significant output, and you should notice a success message <font color='green'>Built cross function flow graph.</font> once finished.

### Taint Analysis

The [`taint`](#taint) command has the same functionality as the [taint analysis tool](taint.md): it runs a taint analysis using the source and sink definitions that are given in the configuration file. For more information about how to use that command, refer to the guide for the [taint tool](taint.md). In the context of the CLI, you should make sure you have run `summarize` and `buildgraph` before running `taint`.
In our running example, running `> taint` will identify four different paths from source to sink. When data from a source reaches a sink, a message of the following form will be printed:
```
 💀 Sink reached at /Users/victornl/repos/argot/testdata/src/taint/example1/main.go:58:7
 Add new path from "[#467.2] (CG)call: invoke stringProducer.source() in fetchAndPut" to "[#462.4] @arg 0:t6 in [#462.3] (SA)call: sink(t6) in main " <==
```
Indicating a path from `stringProducer.source()` to `sink` here. If the options in the configuration file have been set, this path will be reported in more detail in the report folder.

# Commands

### Buildgraph

`buildgraph` builds the inter-procedural dataflow graph using all the functions that have been summarized. You should first run the `summarize` command, at least on all the functions that you want to appear in the dataflow graph. Building the dataflow graph also makes the information reported by the [`callers`](#callers) and [`callees`](#callees) commands more precise. This step is also necessary to run the taint analysis.

### Callees
`callees` expects an argument interpreted as a regex that indicates for which functions the callees need to be printed. If [`buildgraph`](#buildgraph) has been called before, it will use the information gathered during the dataflow analysis to print the callees. Otherwise, it will use the pointer analysis information.

### Callers
`callers` expects an argument interpreted as a regex that indicates for which functions the callers need to be printed. If `buildgraph` has been called before, it will use the information gathered during the dataflow analysis to print the callers. Otherwise, it will use the pointer analysis information.

### Cd

`cd` changes the working directory to the relative directory provided as argument. Remark that the paths to the config file and the program are not updated, and therefore one should call [`load`](#load) and [`reconfig`](#reconfig) with the new relative path if the program and config need to be reloaded from disk.

### Exit
`exit` exits the CLI.

### Focus
`focus` put the CLI in focus mode. It expects one argument, a regex that matches a single function in the program. If the regex matches more than one function, it will print an error message as well as all the matches. Once the CLI is in focus mode, the prompt should be prefixed with the name of the function (without the package name). To exit focus mode, use `unfocus`.

### Help
`help` prints a help message listing all the commands available and a brief summary of their usage.

### List
`list` lists all the functions in the program. Any additional argument provided is read as a regex, and filters the results printed. The user can additionally provide the following flags:
- `-h` to print the help message.
- `-s` to list only *summarized* functions.
- `-r` to list only *reachable* functions.

### Load
`load` loads a program. It expaects an argument, the path to the program to load, relative to the current directory or absolute.

### Ls
`ls` lists the files and directories in the current working directory if no argument is provided, or in the relative directory specified as an argument. This is useful in a pinch if you need to remember where the configuration is relatively to the working directory, for example.

### Pkg
[Focused mode] `pkg` prints the package of the current function, in focused mode.

### Rebuild
`rebuild` reloads the program using the path to the program currently loaded, reading all source files and recomputing the results of the main analyses that are performed when the tool is first loaded. After rebulding, function summaries are kept but they do not match the new program that has been loaded. They can be inspected for comparison, but they should be rebuilt if any analysis that consumes them is called (`summarize` and `buildgraph` should be called again).

### Reconfig

`reconfig` reads the config from disk; if a path argument is specified, then it reads the config file at that path, otherwise it reads the config file currently loaded.

### Showssa
`showssa` accepts one argument, a regex filtering the functions for which to show their SSA representation.

### Ssaval
[Focused mode] `ssaval` shows information about all the values matching the regex provided as argument. This information contains the kind of value in the SSA representation, the type of the values, its location and defining instruction (if available), and finally aliasing information.

## Ssainstr
[Focused mode] `ssainstr` shows information about all the instruction matching the regex provided as argumnet. It will print all the matching instructions in the SSA and show their location in the source code.

### State
`state?` prints a summary of the state of the tool including:
- the path to the program currently loaded.
- the path to the condiguration file currently loaded.
- the current working directory.
- the function currently in focus, if any, or "none".
- the number of functions in the SSA representation of the program.
- the number of summaries that have been built.
- whether the flow graph has been built.

### Stats
`stats` prints statistics about the program. It has a few subcommands:
- `help` prints a help message.
- `all` prints general and closure stats
- `general` prints general stats about the SSA program
- `closures` prints stats about closures with additional options for verbose output:
    - `--filter` to filter output
    - `-U` to print unclassified closures locations
    - `-C` to print anonymous functions capturing channels
    - `-I` to print closures called immediately after creation

### Summarize

`summarize` builds the dataflow summaries of the functions matching the regex provided as argument, or all the functions that should be summarized according to the configuration if no argument is provided. For more information about the summarization, refer to the guide for the [taint analysis tool](taint.md).

### Summary

`summary` displays the dataflow summaries of each function matching the argument provided as regex. If no summaries have been found, then it displays <font color='green'>No summaries found. Consider building summaries (summarize).</font>. If no functions match the regex, then it displays <font color='green'>No matching functions.</font>

### Taint
`taint` runs the taint analysis on the inter-procedural flow graph that has been built by [`buildgraph`](#buildgraph) using the information stored in the loaded configuration.

### Unfocus
`unfocus` exits *focused* mode.

### Where
`where` prints the location of a function. In *focused* mode, it prints the location of the function in focus. Otherwise, it expects an additional argument that is interpreted as a regex matching the function names whose locations will be printed.