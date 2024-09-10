# Package Scanner

packagescan is a tool that searches the codebase of a program and identifies each package that imports a specific target package.  It was originally written to locate all the places where "unsafe" or "reflect" are used in a program.

As with the other AR-Go-Tools, packagescan works at the whole program level.  When invoked it will attempt to build the program arguments provided and then iterate through each package that contributed code to the build.  It will search the imports of those packages and enumerate all the packages that contain an import of the target package.  

By default, it attempts to find an exact match of a single target package.  If no package is supplied it will default to targeting "unsafe".  This can be overriden with the -p flag (e.g.`-p reflect`).  Because many third-party packages are supplied as a tree of subpackages, packagescan offers the -i (inexact) flag that will match any package with the specified prefix.  Thus `argot packagescan -i -p math ...` will report on those packages that import `math`, `math/big`, `math/rand`, etc.  And `argot packagescan -i -p github.com/aws/aws-sdk-go` will locate any package in the program that depends on any part of the AWS SDK.

Unlike the other AR-Go-Tools, packagescan can perform the analysis on more than one target platform.  By default, packagescan will execute the same analysis three times, using `GOOS=darwin`, `GOOS=windows`, and `GOOS=linux`.  It will present the output as a table, allowing you to see all the instances of e.g. `unsafe` in a multi-target codebase.  The platforms can be restricted with the -target option.

The -rawfile option is not yet fully implemented and will dump each observation of a public symbol from the target package(s) to a file.  So for example instead of just seeing which packages import the S3 service, you could see precisely which S3 APIs are called from within the program and from what functions.

The example output below illustrates running packagescan on itself with the default to report on any packages reachable from the code that import "unsafe" and thus might warrant greater scrutiny.  The differences between Windows and Unix are dramatic, but there are even subtle differences between Unix variants.   Note that the table repeats the platform name rather than using column headers and "X" to indicate inclusion because column headers tend to scroll offscreen.  
````
$ argot packagescan ./cmd/argot

Scanning sources for unsafe
Analyzing for windows
Analyzing for linux
Analyzing for darwin
darwin  linux  windows  golang.org/x/sys/execabs
               windows  golang.org/x/sys/internal/unsafeheader
darwin  linux           golang.org/x/sys/unix
               windows  golang.org/x/sys/windows
darwin  linux  windows  golang.org/x/tools/go/types/objectpath
darwin  linux  windows  golang.org/x/tools/internal/event/core
darwin  linux  windows  golang.org/x/tools/internal/event/label
darwin  linux  windows  golang.org/x/tools/internal/tokeninternal
darwin  linux  windows  golang.org/x/tools/internal/typesinternal
darwin  linux  windows  internal/abi
darwin  linux  windows  internal/bytealg
darwin  linux  windows  internal/godebug
               windows  internal/intern
darwin  linux  windows  internal/poll
darwin  linux  windows  internal/race
darwin  linux  windows  internal/reflectlite
               windows  internal/syscall/execenv
darwin  linux           internal/syscall/unix
               windows  internal/syscall/windows
               windows  internal/syscall/windows/registry
darwin  linux  windows  internal/unsafeheader
darwin  linux  windows  math
darwin  linux  windows  math/bits
darwin  linux  windows  math/rand
               windows  net
darwin  linux  windows  os
darwin  linux  windows  reflect
darwin  linux  windows  runtime
darwin  linux  windows  runtime/internal/atomic
        linux           runtime/internal/syscall
darwin  linux  windows  strings
darwin  linux  windows  sync
darwin  linux  windows  sync/atomic
darwin  linux  windows  syscall
darwin  linux  windows  time
````
