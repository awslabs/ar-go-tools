
# Argot CLI

The command line tool `argot cli` (the CLI) provides many commands to help programmers understand the analyses performed by other tools in Argot. In order to use the CLI effectively, you should have a high-level understanding of static analysis techniques. More precisely, you should have an understanding of what the SSA representation of a program is to use the SSA related tools, and an understanding of dataflow analysis techniques in order to use the dataflow analysis related tools. The CLI is a great tool if you want to modify the algorithms on your own, and you need to debug the results. The main motivation is that the results of the analyses can be computed incrementally, and results of interest can be recomputed on demand.

Like many of the tools there,
it must be started with a *program to analyze* and *a configuration file*. To start the `argot cli` with some program `main.go` and some configuration file `config.yaml`:
```shell
argot cli -config config.yaml main.go
```
> If you installed the CLI using `make install`, then call `argot cli`. If you only built the cli using `make argot-build`, look for the executable `./bin/argot`

We will illustrate all the features of the CLI through an example in this document. For a complete list of the commands available in the CLI, type `help` once the program has started and the prompt starting with `>` appears.
Type [`exit`](#exit) in the prompt to exit the CLI.
You can also have a look at [the documentation](../cmd/argot/cli/doc.go) of the executable, or the [list of commands](#commands) at the end of this section.

Each command may accept arguments, flags and/or named arguments, separated by spaces:
- flags are strings preceded with a single dash, e.g. `-v`.
- named arguments are a pair of a string preceded with two dashes, e.g. `--filter`, the name of the argument, and the string following immediately after, the value of the argument,
- the rest of the strings are interpreted as arguments.


# Detailed Example: Loading `analysis/taint/testdata/example1`

First, we use the CLI to load the Go program in `analysis/taint/testdata/example1`:
```shell
argot cli -config ./analysis/taint/testdata/example1/config.yaml ./testdata/src/taint/example1/main.go
```
> 📝 If the program is only a `main.go` file and there is a file `config.yaml` in the same directory, then you can omit the `-config ...`. In the example above, using `argot cli ./analysis/taint/testdata/example1/main.go` will load the same program with the same configuration.

You should see first a few lines of output that explain what the tool is analyzing. First, a `Reading sources` message will indicate that the tool is reading the sources. It should be followed by messages similar to the following:
```
[INFO]  Gathering global variable declaration in the program...
[INFO]  Gathering values and starting pointer analysis...
[INFO]  Computing information about types and functions for analysis...
```
With matching messages that indicate each of the analyses (pointer analysis, global variable collection, type and function collection) terminate. Finally, the tool looks where variables are bound by some closure in the code.
All the analyses should take less than a second in total for this simple example, but for larger programs, it can take minutes!
If everything runs successfully you should be presented with a prompt:
```
[INFO]  Pointer analysis terminated (0.13 s)
>
```
And you can start querying and rendering the state of the analyses, as well as run other analyses.


## First Steps: State, Statistics and Utilities

First, let us have a look at a few commands that let you inspect the current state of the tool and change some basic information about it.

The [`state?`](#state) command print information about the current state of the tool, including the path to the program it is analyzing, the path to the configuration file and the working directory.
In our example, assuming `<somedir>` is the root directory of the repository:
```
> state?
Program path      : ./analysis/taint/testdata/example1/main.go
Config path       : ./analysis/taint/testdata/example1/config.yaml
Working dir       : <somedir>
Focused function  : none
# functions       : 5467
# summaries built : 0
flow graph built? : false
```
The first lines of output are self-explanatory. We will see later how to *focus* on a specific function; for now, there is no focused function. `state?` also prints the number of functions in the loaded program, and the number of dataflow summaries that have been built and whether the inter-procedural dataflow graph has been built. These last two parts are specific to the dataflow-based analyses, such as the [taint analysis](01_taint.md#taint-analysis) and the [backwards flow analysis](02_backtrace.md#backtrace-analysis).


### Utilities
The tool provides a few utilities to change directories, reload config files and programs:
- You can reload the configuration from disk at any point by using the [`reconfig`](#reconfig) command. It optionally accepts an argument that is a path to a new configuration file.
- You can rebuild the program using [`rebuild`](#rebuild) or load a new program using [`load`](#load). This allows you to modify the source code of the program you are analyzing and reload it without leaving the CLI.
- The [`ls`](#ls) command lists directories and files in the current working directory.
- If you want to change the working directory, use the [`cd`](#cd) command, for example:
```
> cd analysis/taint/testdata/example1
```
If you have changed directory and need to reload the config file or the program, you will need to respecify the paths, for example `> reconfig config.yaml` in this case to reload the config file. Calling `> rebuild` would fail here, so you need to first load the program relatively to the new location by using `> load main.go` (and any subsequent call to `> rebuild` will succeed, provided the program can be compiled, and you have not changed location).


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
Additionally, `stats` has a few *subcommands*: `help`, `all`, `general` and `closures`. `stats help` prints a help message that explains those options.  The `general` statistics are the ones printed by the command without subcommands. `stats closures` prints more information about closure usage and number of closures in the code. `stats all` prints both general and closure statistics.
For the `closure` subcommand, several flags can be used to print locations of closure usage (`-U`, `-C` and `-I`). Their definition is accessible by typing `stats help`.
To print all information, type:
```
> stats all -U -C -I
```
In our example, there is only a few closures and this reports only two anonymous functions capturing channels.
> 📝 Command flags such as `-U`, `-C` and `-I` above always need to be specified separately with their preceding dash. Commands like `stats` can also accept a name argument `--filter something`. Try running `stats all -U -C -I --filter Read`.


## Inspecting The SSA

The CLI provides a number of commands to inspect the SSA representation of the code, as well as the results of the pointer analysis.
An entry point to looking more precisely at those function is to use the [`list`](#list) command, which lists all the functions in the program, possibly with some filters.
The arguments provided to the commands are interpreted as regexes, and used as filters on the output. For example, the functions in the `main` package of the program are loaded in the `command-line-arguments` package. You can list them using:
```
> list command-line-arguments.*
```
Alternatively, using a shorter regex, e.g. calling `list com.*ts.`, would work just as well. Note that in terminals that support escape codes, some functions might appear in different colors to highlight whether those functions are *reachable* and/or *summarized*. The first two elements of each line also  indicate whether a function is summarized `[x][_]` or reachable `[_][x]` or both `[x][x]`. Initially, you should see an output of the form:
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
Location: /<somedir>/analysis/taint/testdata/example1/main.go:64:6
```
This shows the location of `test2` in the source code. The argument is interpreted as a regex, and the location of any function whose name matches the regex will be printed.


To show the SSA representation of a function, use the [`showssa`](#showssa) command. For example, the command:
```
> showssa test2
```
Will print the SSA representation of the `test2` function. The argument provided to `showssa` is interpreted as a regex; any function matching that regex will be printed in the terminal. For more information about the representation, refer to the [ssa package](https://pkg.go.dev/golang.org/x/tools/go/ssa#section-documentation).


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
         - position: /<somedir>/analysis/taint/testdata/example1/main.go:59:7
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
The CLI prints a response that shows is has successfully loaded the function. The prompt should now be prefixed by the name of the function.

> ⚠  The argument of focus is interpreted as a regex (as in most cases in the CLI) but only one function must match that regex. For example, if the focus command is called with `test` as argument in the example, you should see an error output that says <font color='red'>Too many matching functions:</font> and then list all the matches. The list of matches should help you refine your regex to match only the function you want. If no function matches the regex, for example if you use the command `focus doesnotexist`, then an error <font color='red'>No matching function.</font> should be printed.

When a function is focused, typing `where` without argument shows the location of the focused function:
```
test2 > where
Location: <somedir>/analysis/taint/testdata/example1/main.go:64:6
```
Similarly, you can use `showssa` without any argument:
```
test2 > showssa
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
      location: /<somedir>/analysis/taint/testdata/example1/main.go:65:2
  referrers:
    [&t0.I [#0]]   [*t0]
  direct aliases:
    [t0 (local fooProducer (w))]
```
The output of the command shows that exactly one value matches the name `t0`; it is an allocation (the kind is `*ssa.Alloc`) of a variable of type `*command-line-arguments.fooProducer`. The instruction also indicates that this is a local variable, since it is defined by the instruction `local fooProducer (w)`. Recall that the SSA representation is defined in the [ssa package](https://pkg.go.dev/golang.org/x/tools/go/ssa).
The instructions that refer to the value `t0` are then displayed: an instruction that takes the address of field `I` of `t0`, and a dereference of `t0` itself. To inspect those instructions, one can use the next command `ssainstr` or look at the ssa (using `showssa`) to see which value it defines.
The final element in the output shows that the only direct alias of `t0` is itself.


- [`ssainstr`](#ssainstr) shows all the SSA instructions matching the regex provided as argument in the focused function. For example, `test2 > ssainstr t1` should print the only instruction that refers to `t1` in the SSA. The matching location in the source code is the location where the struct field is set to 1.
- [`pkg`](#pkg) shows the package of the current function.

At any point, you can exit *focused* mode by using the [`unfocus`](#unfocus) command:
```
test2 > unfocus
Unfocus test2.
```

## Running Dataflow Analyses

The first step that should be taken in order to run dataflow analyses is to build the dataflow summaries of the functions of interest in the program. The [`summarize`](#summarize) command does exactly that: it builds the summaries for all functions of interest, according to the config file, when no argument is specified. If some argument regex is specified, then it builds the summaries for only the functions matching the regex. For more information on what parts of the configuration file are relevant, refer to the guide on using the [taint analysis](01_taint.md#taint-analysis) tool.

For example, you can summarize the `test2` function:
```
> summarize test2
Running intra-procedural analysis on functions matching test2
1 summaries created, 1 built.
```
Then, if you call `> list test2` you should observe that the function is summarized, witnessed by the line `[x][x] command-line-arguments.test2` in the output. Summaries can be inspected using the [`summary`](#summary) command.
In this example:
```
> summary test2
Found summary of example1.test2:
Nodes:
         "[#846.0] (SA)call: (fooProducer).source(t3) in test2"
         "[#846.1] @arg 0:t3 in [#846.0] (SA)call: (fooProducer).source(t3) in test2 "
         "[#846.2] (SA)call: f(t5, "ok":string) in test2"
         "[#846.3] @arg 0:t5 in [#846.2] (SA)call: f(t5, "ok":string) in test2 "
         "[#846.4] @arg 1:"ok":string in [#846.2] (SA)call: f(t5, "ok":string) in test2 "
         "[#846.5] (SA)call: sink(t6) in test2"
         "[#846.6] @arg 0:t6 in [#846.5] (SA)call: sink(t6) in test2 "
Summary of test2:
  Call "[#846.0] (SA)call: (fooProducer).source(t3) in test2":
    (#0) -> "[#846.3] @arg 0:t5 in [#846.2] (SA)call: f(t5, "ok":string) in test2 "
  Call "[#846.2] (SA)call: f(t5, "ok":string) in test2":
    (#0) -> "[#846.6] @arg 0:t6 in [#846.5] (SA)call: sink(t6) in test2 "
(1 matching summary)
```
Shows that there are two dataflow edges in the dataflow summary of `test2`. The first edge indicates that the result of the call to `(fooProducer).source` flows to the argument `t5` (at position 0) in the call to `f`. The second edge indicates that the result of the call to `f` flows to the argument `t6` (also at position 0) in the call to `sink`.

To summarize all functions, call `> summarize`. 12 summaries should have been built by this step. This step is an *intra-procedural* analysis step: every function is analyzed individually, without considering the other functions. To perform a full program analysis, we need to link those summaries together.

The [`buildgraph`](#buildgraph) command builds *inter-procedural* edges between the summaries; it links function calls in one summary to the summary of the function being called. As such, it makes sense to run `buildgraph` only after you have run `summarize`. Running `> buildgraph` does not produce significant output, and you should notice a success message <font color='green'>Built cross function flow graph.</font> once finished.

### Inspecting The Intra-Procedural Analysis

The CLI exposes functionality to help inspect the intermediate state of the intra-procedural dataflow analysis, which can be a useful tool to understand the final result or debug the algorithm when you want to modify it. The intra-procedural analysis focuses on a single function, and to run it with the debugging output, you should be focused on the specific function.
Assuming we want to inspect the analysis result on the `test2` function, we need to first focus on it:
```
> focus test2
Focusing on command-line-arguments.test2.
```
Once we are in focused mode, the [`intra`](#intra) command will run the analysis and print the final state of the dataflow analysis, from which the summary would be built. Running it on our example looks like:
```
test2 > intra
[function test2]
• instruction local fooProducer (w) @ /Users/victornl/repos/argot/analysis/taint/testdata/example1/main.go:65:2:
<additional output>
• instruction sink(t6) @ /Users/victornl/repos/argot/analysis/taint/testdata/example1/main.go:68:6:
   "ok":string                    marked by 🏷 arg: "ok":string in f(t5, "ok":string)
   t2=local wrappedString (s)     marked by 🏷 multiple: (fooProducer).source(t3) #0
   t3=*t0                         marked by 🏷 arg: t3 in (fooProducer).source(t3)
   t4=(fooProducer).source(t3)    marked by 🏷 multiple: (fooProducer).source(t3) #0
   t5=*t2                         marked by 🏷 arg: t5 in f(t5, "ok":string) & 🏷 multiple: (fooProducer).source(t3) #0
   t6=f(t5, "ok":string)          marked by 🏷 call: f(t5, "ok":string) #0 & 🏷 arg: t6 in sink(t6)
   t7=sink(t6)                    marked by 🏷 call: sink(t6)
  ```
  The final state of the analysis is the set of marked values that reach the function's values, at each instruction of the function. At each instruction in the SSA representation of the function (e.g. the function call `sink(t6)` in the example), there are several values defined (here, the values from `t0` to `t7`). Each value can be *marked* with a label, represented here with the objects starting with `🏷`. When a value is marked with a label, that means the data of the object represented by the label flows to the value. Each label has a kind, one of:
  - "parameter" if it is a parameter of the function being analyzed,
  - "freevar" if it is a free variable,
  - "arg" if it is the argument in a function call,
  - "call" if it is the result of a function call,
  - "return" if it appears in one return of the function,
  - "boundvar" if it is bound by a closure,
  - "closure" if the value is a closure,
  - "synthetic" if the value corresponds to a node that has been synthetically added (such as some field accesses),
  - "global" if the value is a global variable,
  - "multiple" if the value has multiple labels.

After the kind of the label, a string representing the value of the label is printed. This can be the instruction that produces the value, or a parameter, or a free variable in the SSA representation of the function. There may be a last element in the label's string representation, the string `#i` where `i` is some positive or zero number representing the index of the tuple element that the label represents.

Recall the following line in the output of the previous code snippet:
```
   t6=f(t5, "ok":string)          marked by 🏷 call: f(t5, "ok":string) #0 & 🏷 arg: t6 in sink(t6)
```
It shows that the value `t6` is reached by the data coming from the result of the call to `f` (the label `🏷 call: f(t5, "ok":string) #0`) and the value of the argument `t6` in the call to sink (the label ` 🏷 arg: t6 in sink(t6)`). This last fact is the more interesting one: it shows that if the call to `sink` writes data to its argument `t6`, then the value `t6` will contain that data after the instruction `sink(t6)`. If you inspect the output of `intra`, you will note that at the previous instruction, we have `   t6=f(t5, "ok":string)          marked by 🏷 call: f(t5, "ok":string) #0` meaning only the result of the call is reaching the value `t6`, as expected.

The state of the analysis can also be printed every time the analyzer has finished analyzing a block. To do that, provide the `-v` flag to the `intra` command.

### Running the Taint Analysis

The [`taint`](#taint) command has the same functionality as the [taint analysis tool](01_taint.md#taint-analysis): it runs a taint analysis using the source, sink and sanitizer definitions that are given in the configuration file. For more information about how to use that command, refer to the guide for the [taint tool](taint.md). In the context of the CLI, you should make sure you have run `summarize` and `buildgraph` before running `taint`.
In our running example, running `> taint` will identify four different paths from source to sink. When data from a source reaches a sink, a message of the following form will be printed:
```
 💀 Sink reached at /Users/victornl/repos/argot/analysis/taint/testdata/example1/main.go:58:7
 Add new path from "[#744.2] (CG)call: invoke stringProducer.source() in fetchAndPut" to "[#626.4] @arg 0:t6 in [#626.3] (SA)call: sink(t6) in main " <==
```
Indicating a path from `stringProducer.source()` to `sink` here. If the options in the configuration file have been set, this path will be reported in more detail in the report folder.

### Running a Custom Dataflow Analysis

The [`trace`](#trace) commands lets the user run more fine-grained analyses, in the context where they are aware of the inner representation of the dataflow graph.
The command requires one argument, a regular expression that matches node ids. For example, suppose we ran the command `>summary test2` listed earlier.
The node ids are for example`#846.1`, `#846.2`, `#846.3` (note that the exact ids will differ between runs).  To trace the dataflow from the call to `f` (node `#461.2`) we can run the following command:
```
> trace 846.3
[INFO]     
****************************** NEW SOURCE ******************************
[INFO]  ==> Source: "[#846.3] @arg 0:t5 in [#846.2] (SA)call: f(t5, "ok":string) in test2 "
[INFO]  Found at /Users/victornl/repos/argot/analysis/taint/testdata/example1/main.go:67:9
[INFO]   💀 Sink reached at /Users/victornl/repos/argot/analysis/taint/testdata/example1/main.go:67:8
[INFO]   Add new path from "[#846.3] @arg 0:t5 in [#846.2] (SA)call: f(t5, "ok":string) in test2 " to "[#846.6] @arg 0:t6 in [#846.5] (SA)call: sink(t6) in test2 " <== 
```
Adding the `-t` option will print all the intermediate states encountered during the traversal. In this case, a sink is reached
immediately. 

# Commands

All available commands are listed here, with more detailed documentation than in the message printed by `help`.

### Buildgraph

`buildgraph` builds the inter-procedural dataflow graph using all the functions that have been summarized. You should first run the `summarize` command, at least on all the functions that you want to appear in the dataflow graph. Building the dataflow graph also makes the information reported by the [`callers`](#callers) and [`callees`](#callees) commands more precise. This step is also necessary to run the taint analysis. If `buildgraph` has been called, then the last line of output when calling `state?` should be `flow graph built? : true`.

### Callees
`callees` expects an argument interpreted as a regex that indicates for which functions the callees need to be printed. If [`buildgraph`](#buildgraph) has been called before, it will use the information gathered during the dataflow analysis to print the callees. Otherwise, it will use the pointer analysis information.

If no argument is provided, `callees` will print the callees of every function in the program.

### Callers
`callers` expects an argument interpreted as a regex that indicates for which functions the callers need to be printed. If `buildgraph` has been called before, it will use the information gathered during the dataflow analysis to print the callers. Otherwise, it will use the pointer analysis information.

If no argument is provided, `callers` will print the callers of every function in the program.

### Cd

`cd` changes the working directory to the relative directory provided as argument. Remark that the paths to the config file and the program are not updated; and therefore one should call [`load`](#load) and [`reconfig`](#reconfig) with the new relative path if the program and config need to be reloaded from disk.

### Exit
`exit` exits the CLI.

### Focus
`focus` puts the CLI in focus mode. It expects one argument, a regex that matches a single function in the program. If the regex matches more than one function, it will print an error message as well as all the matches. Once the CLI is in focus mode, the prompt should be prefixed with the name of the function (without the package name). To exit focus mode, use [`unfocus`](#unfocus).

### Help
`help` prints a help message listing all the commands available and a brief summary of their usage.

### Intra
[Focused mode] `intra` runs the intra-procedural analysis on the focused function and prints the final state of the analysis. With the `-v` option, the state will be printed every time the analyzed has finished analyzing a block. Since this analysis is implemented using the monotone framework, a block will likely be analyzed multiple times. The output of the command with `-v` should be used only on simple function where the number of blocks is small.
The output of the `intra` command prints:
- for each instruction in the function, a line of the form `• instruction <instruction string> (w) @ <instruction location>`, where:
  - `<instruction string>` is a string representation of the instruction, defined by the [ssa package](https://pkg.go.dev/golang.org/x/tools/go/ssa#Instruction).
  - `<instruction location>` is the location of the instruction in the source code. If the SSA instruction has no corresponding location in the source code, `-` will be printed.
- after each instruction line, and for each value that is tracked at the instruction, a line of the form `<value string> marked by <list of labels>`, where:
  - `<value string>` is a string representation of the SSA value.
  - `<list of labels>` is a list of data labels separated with `&`, each label starting with `🏷`.  For more information on the labels, please refer to the section on [inspecting the intra-procedural analysis](#inspecting-the-intra-procedural-analysis).

### List
`list` lists all the functions in the program. If an argument is provided, it is read as a regex, and only function whose complete name (including the package name) match the regex will be printed.
The user can additionally provide the following flags:
- `-h` to print the help message.
- `-s` to list only *summarized* functions.
- `-r` to list only *reachable* functions.

### Load
`load` loads a program. It expects an argument, the path to the program to load, relative to the current directory or absolute. The `load` command will call `rebuild` once it has changed the state of the CLI.

### Ls
`ls` lists the files and directories in the current working directory if no argument is provided, or in the relative directory specified as an argument. This is useful in a pinch if you need to remember where the configuration is relatively to the working directory, for example.

### Pkg
[Focused mode] `pkg` prints the package of the current function, in focused mode.

### Rebuild
`rebuild` reloads the program using the path to the program currently loaded, reading all source files and recomputing the results of the main analyses that are performed when the tool is first loaded. After rebuilding, function summaries are kept, but they do not match the new program that has been loaded. They can be inspected for comparison, but they should be rebuilt if any analysis that consumes them is needed (`summarize` and `buildgraph` should be called again).

### Reconfig

`reconfig` reads the config from disk; if a path argument is specified, then it reads the config file at that path, otherwise it reads the config file currently loaded.

### Showssa
`showssa` accepts one argument, a regex filtering the functions for which to show their SSA representation. For each function in the program, its SSA representation is printed if its complete name matches the regex.

### Showdataflow
`showdataflow` builds and prints the inter-procedural dataflow graph of a complete program. You should run [`summarize`](#summarize) before this command.

### Showescape
`showescape` prints the escape graph of the functions matching the regex provided as argument.

### Ssaval
[Focused mode] `ssaval` shows information about all the values matching the regex provided as argument. This information contains the kind of value in the SSA representation, the type of the values, its location and defining instruction (if available), and finally aliasing information.

### Ssainstr
[Focused mode] `ssainstr` shows information about all the instruction matching the regex provided as argument. It will print all the matching instructions in the SSA and show their location in the source code.

### State
`state?` prints a summary of the state of the tool including:
- the path to the program currently loaded.
- the path to the configuration file currently loaded.
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

`summarize` builds the dataflow summaries of the functions matching the regex provided as argument, or all the functions that should be summarized according to the configuration if no argument is provided. For more information about the summarization, refer to the guide for the [taint analysis tool](01_taint.md#taint-analysis).

> When the `dataflow-problems` option `summarize-on-demand` is set to `true`, the `summarize` command does not run the intra-procedural analysis, it only builds the data-structure necessary to summarize the function later.

### Summary

`summary` displays the dataflow summaries of each function matching the argument provided as regex. If no summaries have been found, then it displays <font color='green'>No summaries found. Consider building summaries (summarize).</font>. If no functions match the regex, then it displays <font color='green'>No matching functions.</font>

### Taint
`taint` runs the taint analysis on the inter-procedural flow graph that has been built by [`buildgraph`](#buildgraph) using the information stored in the loaded configuration.

### Trace 
`trace` runs an inter-procedural dataflow analysis starting from every node with an id matching the provided argument. The `-t` option allows the tool to print trace-level information while the analysis runs.

### Unfocus
`unfocus` exits *focused* mode.

### Where
`where` prints the location of a function. In *focused* mode, it prints the location of the function in focus. Otherwise, it expects an additional argument that is interpreted as a regex matching the function names whose locations will be printed.
