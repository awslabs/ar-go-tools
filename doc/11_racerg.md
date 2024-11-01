# Racerg: Sound And Scalable Static Data Race Detector For Go

The `racerg` tool implements a sound and scalable static data race detector for Go. This tool is experimental, and as such has limited support for the features of the Go language. However, this limited supports affords the tool much stronger guarantees about its results. `racerg` is a static analysis tool, as opposed to the race detector in the Go language, which is dynamic. As opposed to the other tools in Argot, `racerg` has a few additional dependencies that the user must install before being able to use the tool.

## Dependencies

1. Soufflé Datalog. We compiled a version on Mac with OpenMP support on a Macbook using

```
brew update
brew install cmake bison libffi mcpp pkg-config
brew reinstall gcc
brew link bison --force
brew link libffi --force

export PKG_CONFIG_PATH=/opt/homebrew/opt/libffi/lib/pkgconfig/
cd souffle
cmake -DSOUFFLE_DOMAIN_64BIT=ON -DCMAKE_C_COMPILER="/opt/homebrew/Cellar/llvm/16.0.4/bin/clang" -DCMAKE_CXX_COMPILER="/opt/homebrew/Cellar/llvm/16.0.4/bin/clang++" -DOpenMP_CXX_FLAGS="-Xclang -fopenmp -I/opt/homebrew/opt/libomp/include" -DOpenMP_C_FLAGS="-Xclang -fopenmp -I/opt/homebrew/opt/libomp/include" -DOpenMP_CXX_LIB_NAMES=libomp  -DOpenMP_C_LIB_NAMES=libomp -DOpenMP_libomp_LIBRARY=/opt/homebrew/opt/libomp/lib/libomp.dylib -DCMAKE_SHARED_LINKER_FLAGS="-L/opt/homebrew/opt/libomp/lib -lomp -Wl,-rpath,/opt/homebrew/opt/libomp/lib"-S . -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j8
sudo cmake --build build -j8 --target install
```

A [pre-compiled binary](https://souffle-lang.github.io/install.html) is available without OpenMP support.

2. The Go language should already be installed on your machine if you are using Argot. If that is not the case, run on MacOs:

```
brew install go
```

## Running

Suppose the project root directory is `/Users/<username>/ar-go-tools` and you have installed `souffle` in `/Users/<username>/souffle`.
An analysis on some example Go source `examples/returnValue.go` can be run using the following command:

```
cd /Users/<username>/ar-go-tools
go run cmd/racerg/main.go -souffle-path=/Users/<username>/souffle/build/src/souffle -souffle-analysis=/Users/<username>/ar-go-tools/analysis.dl -roots-path=/Users/<username>/ar-go-tools/roots.csv -mod=/Users/<username>/ar-go-tools/examples -output=./output/ /Users/<username>/ar-go-tools/examples/returnValue.go
```

Explanations of the available command line flags are as follows:

```
Usage:

go run main.go [flags] [source ...]

The flags are:

-mod
The path to the Go module to be analyzed.

-ssaline
Print the line-by-line SSA and the generated fact, for debugging.

-ssafunc
Before printing the debugging information for each instruction in a function,
print SSA for the whole function using the Go ssa package.

-souffle-path
Path to the souffle executable.

-souffle-analysis
Path to the main souffle analysis (.dl).

-output
Path to a directory used to store the generated facts.

-roots-path
Provide a csv file for the entry functions to analyze.
Each function is on a separate line.
A default root file would be a csv with just one line that indicates
analysis starts with the main function in the main package, or "main.main".
```

## Architecture

The implementation consists of a fact generator `cmd/racerg/main.go`, which encodes information about the Go SSA
program and writes it to the output folder; and the Soufflé Datalog based analysis `analysis.dl`.
Documentation is available along with the source.