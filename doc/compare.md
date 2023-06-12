The `compare` tool is used to compare different reachability strategies in order to drill down into their differences in the context of a single target program.  It can be used in one of two modes.

When invoked with the `-symbols` argument, the compare tool compares functions that are reachable within the target program -- using three different algorithms -- against the functions that are linked into the binary by the compiler.  This tool exists to allow somebody working with these analysis tools to understand the differences in these algorithms in order to make a well-informed choice of which to use.  

The first algorithm is the `ssautil.AllFunctions` provided in x/tools.  This is described as "the set of functions potentially needed by program prog, as determined by a simple linker-style reachability algorithm starting from the members and method-sets of each package."  This is an extremely conservative algorithm that includes virtually everything in each imported package.

The second algorithm is the less conservative `reachability` algorithm used in the `dependencies` and `rechability` tools.  This starts with the init & main functions and walks each function that can be the target of a function call -- either directly or using an interface -- or can be passed as a value -- again either directly or using an interface.  One significant difference between this approach and AllFunctions is that the latter will include every method of an interface, even if those methods cannot be invoked.  The `reachability` algorithm will include any member function that is observed to be invoked of any object that matches that interface.

The third algorithm uses the call-graph analysis for even more accurate reachability.  This takes much longer to execute and can be tripped up by the use of reflection and unsafe code.  But the results are much more precise because they only include calls to interface functions that are observed to be possible run-time values of those dynamic targets.  This thirs algorithm defaults to the x/tools pointer analysis, but can be overridden using one of `cha, rta, static, vta` with the `-analysis` flag. 

All three of these can be optionally compared against the "ground truth" offered by the symbol table of the actual compiled binary.  This is more complex because it requires that the binary be built and the symbol table dumped using the `go tool nm`.  It also is less accurate because (a) the symbols in the binary use a slightly different naming convention than that used by x/tools, (b) the binary will appear to not contain functions that were actually inlined by the compiler, and (c) the binary includes lower-level (e.g. hash and equality) functions that are automatically created.  However it can be very useful in terms of locating opportunities for refactoring the code to reduce bloat when functions that aren't needed are included in the binary because the compiler can't tell that they aren't required.

To run the compare tool with all four possibilities against (for example) the reachability tool, perform the following steps:
```
go build ./cmd/reachability/
go tool nm ./reachability > reachability.symbols
bin/compare -symbols -binary reachability.symbols ./cmd/reachability 
```

The output is presented in a tabular form with one row for each function that appears in any of the four approaches and columns indicating with it appears in: 
 A - AllFunctions
 r - reachability
 c - callgraph analysis
 s - the symbol table of the binary  

