# Compare Tool

The `compare` tool is used to compare different reachability strategies in order to drill down into their differences in the context of a single target program.  It can be used in one of two modes: symbols mode and dynamic callgraph mode

## Symbols Mode

When invoked with the `-symbols` argument, the compare tool compares functions that are reachable within the target program -- using three different algorithms -- against the functions that are linked into the binary by the compiler.  This tool exists to allow somebody working with these analysis tools to understand the differences in these algorithms in order to make a well-informed choice of which to use.  

The first algorithm is the `ssautil.AllFunctions` provided in x/tools.  This is described as "the set of functions potentially needed by program prog, as determined by a simple linker-style reachability algorithm starting from the members and method-sets of each package."  This is an extremely conservative algorithm that includes virtually everything in each imported package.

The second algorithm is the less conservative `reachability` algorithm used in the `dependencies` and `reachability` tools.  This starts with the init & main functions and walks each function that can be the target of a function call -- either directly or using an interface -- or can be passed as a value -- again either directly or using an interface.  One significant difference between this approach and AllFunctions is that the latter will include every method of an interface, even if those methods cannot be invoked.  The `reachability` algorithm will include any member function that is observed to be invoked of any object that matches that interface.

The third algorithm uses the call-graph analysis for even more accurate reachability.  This takes much longer to execute and can be tripped up by the use of reflection and unsafe code.  But the results are much more precise because they only include calls to interface functions that are observed to be possible run-time values of those dynamic targets.  This third algorithm defaults to the x/tools pointer analysis, but can be overridden using one of `cha, rta, static, vta` with the `-analysis` flag. 

All three of these can be optionally compared against the "ground truth" offered by the symbol table of the actual compiled binary.  This is more complex because it requires that the binary be built and the symbol table dumped using the `go tool nm`.  It also is less accurate because (a) the symbols in the binary use a slightly different naming convention than that used by x/tools, (b) the binary will appear to not contain functions that were actually inlined by the compiler, and (c) the binary includes lower-level (e.g. hash and equality) functions that are automatically created.  However, it can be very useful in terms of locating opportunities for refactoring the code to reduce bloat when functions that aren't needed are included in the binary because the compiler can't tell that they aren't required.

To run the compare tool with all four possibilities against (for example) the argot tool, perform the following steps:
```shell
go build ./cmd/argot
go tool nm ./argot > argot.symbols
argot compare -symbols -binary argot.symbols ./cmd/argot
```

The output is presented in a tabular form with one row for each function that appears in any of the four approaches and columns indicating with it appears in: 
 A - AllFunctions
 r - reachability
 c - callgraph analysis
 s - the symbol table of the binary  

## Dynamic Callgraph Mode

The dynamic callgraph mode compares the statically computed callgraph (specified with the `-analysis` flag) to a dynamic callgraph obtained by e.g. instrumenting a binary. The graphs are compared by looking at the edges, i.e. calls from one function to another. For example, if we have:

```go
func f() {
    g(); // line 2
}
func g() {
    h(); // line 5
}
func h() {} // line 7
```

then we expect edges from `f -> g` and `g -> h`. If dynamically we observe an edge `a -> b` that isn't part of the statically computed callgraph, then we would have a potential unsoundness in the static callgraph. The dynamic callgraph is represented by a set of files of the form `callgraph-BINARY-[0-9]+.out`, where BINARY is the name of the binary file supplied with `-dynbinary`. (`-dynbinary` is solely used as way to identify the correct callgraph files; it does not need to name a file and no attempt to load the file is made.) The appropriate callgraph files will be loaded from the directory specified by the `-callgraphs` argument.

Each file should contain lines of the form `file.go:line -> file.go:line`, where the first file/line is the callsite, and the second file/line is the callee. For example, the edge `f -> g` from the example above will be `main.go:2 -> main.go:4`, because the callsite is on line 2 and `g` is declared on line 4. Similarly, there will be a line `main.go:5 -> main.go:7` for the call from `g` to `h`. Because the matching is done by file/line information, the source code analyzed and the binary should correspond exactly for accurate results.

The tool then analyzes the dynamic edges to determine whether they are a subset of the possible edges reported by the static callgraph. Edges missing from the static callgraph represent possible unsoundness in the static callgraph, i.e. places where the static callgraph says no call is possible between two functions, but there is an observed call between them. This would typically occur with indirect calls like interface methods or closures. Missing edges may not represent actual unsoundness for a few reasons:
- inlining, where the dynamic edge will cross multiple levels of the static graph
- runtime functions, where the actual stack has extra calls used to implement go level semantics
- certain autogenerated functions, that can't be lined up by file:line positions
- implementations of runtime functions that are treated specially by the pointer analysis
- low level calls inserted directly by the runtime (e.g. godebug related and init functions)

Some attempt to filter common classes of these false positives has been made. It is also possible to have false negatives, due to the file/line matching. For example, if there are two callsites on the same line, and the same function `f` can be called from both, the static analysis may incorrectly claim only one callsite can call `f`. This would not be caught with a dynamic edge because the line information does not distinguish between the two callsites.

The tool can be run by e.g.:

```shell
argot compare -callgraphs /tmp/callgraph-logs -dynbinary main src/main.go
```

The result will be a listing of some basic statistics, followed by missing edges, if any:

```
Reading sources
Computing call graph
Computed in 0.129 s
Found total of 17 dynamic edges
Removed 7 edges for init functions
Removed 0 edges for goroutines
Removed 0 edges for map hasher
Remaining dynamic edges: 0 of 17
<no dynamic edges not covered by a static edge>
```

If there are missing edges, they will be reported as:

```
...
Remaining dynamic edges: 1 of 18
  main.go:15 -> goroot/src/os/file_unix.go:203
```
