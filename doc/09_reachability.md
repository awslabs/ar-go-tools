
# Reachability Tool

Several of the Argot tools use the reachability algorithm in analysis/reachability.  This algorithm performs a whole-program analysis of which functions are called either directly or via an interface.  It is less conservative than the x/tools AllFunctions but more conservative than the pointer analysis.  

The reachability tool is a thin wrapper around the reachability algorithm, dumping a complete list of every function that the algorithm considers to be reachable.  The tool exists to allow deep dives into the results of other tools, such as dependencies or packagescan.  While other tools can provide a summary of package reachability, the reachabilty tool can provide the supporting function-level data which can then be filtered to determine which specific functions are responsible for package inclusion.  

The reachability tool reports on every function that it deems reachable from either the global initialization function (main.init) or the global main function (main.main).  In order to understand which functions are reachable from each of these, it supports two command line arguments to suppress starting from main.init (-noinit) or main.main (-nomain).  

Running reachability three times with (a) no arguments, (b) -noinit, and (c) -nomain and piping the output through wc gives the size of the set of functions reachable from both, from main, and from  init.  Subtracting the latter two from the first gives the number of functions reachable from only init and only main.  This can help in understanding side effects incurred from merely importing a package.

The reachability algorithm is only one estimate of which functions are needed in the program.  It differs from the estimate offered by the pointer analysis and from which functions are actually linked into the binary by the compiler.  The `compare` tool is provided to better understand these differences.  

For example, running the tool on Argot itself should look like:
```shell
argot reachability ./cmd/argot | head -n 40
Reading sources
[WARN]  possible annotation mistake: // The function checks the annotations to suppress reports where there are //argot:ignore annotations. has "argot" but doesn't start with //argot:
[INFO]  Loaded 0 annotations from program
Analyzing
[INFO]  16700 SSA functions
[INFO]  2 entrypoints
[INFO]  9690 reachable functions
(*bufio.Reader).Buffered
(*bufio.Reader).Read
(*bufio.Reader).ReadByte
(*bufio.Reader).ReadRune
(*bufio.Reader).ReadSlice
(*bufio.Reader).fill
(*bufio.Reader).readErr
(*bufio.Reader).reset
(*bufio.Scanner).Err
(*bufio.Scanner).Scan
(*bufio.Scanner).Split
(*bufio.Scanner).Text
(*bufio.Scanner).advance
(*bufio.Scanner).setErr
...
```