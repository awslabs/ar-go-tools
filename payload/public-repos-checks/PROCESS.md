# Dataflow Summary Generation Process

This document describes the process for generating dataflow summaries for Go functions to be used with the Argot taint analysis tool.

## Overview

Dataflow summaries describe how data flows through a function - which inputs affect which outputs. They are essential for sound taint analysis when functions cannot be analyzed directly due to unsafe operations, complex control flow, or other limitations.

## Process Steps

### 1. Load the Program
```bash
argot_load ["./path/to/program"]
```

### 2. Run Initial Taint Analysis (with timeout)
```bash
timeout 60s argot taint -config argot-config.yaml 2>&1 | grep WARN
```

**Important**: Use a timeout (e.g., 60 seconds) for the first few runs, as the analysis might take a very long time without summaries. Once you have basic summaries in place, you can remove the timeout.

This identifies functions that need summaries. Look for warnings like:
```
[WARN].package-name Function package.FunctionName should have a summary:
```

### 3. Extract Function List
From the warnings, create a list of functions that need summaries. Skip functions with `$bound` suffix as they are compiler-generated.

### 4. Analyze Each Function

For each function that needs a summary:

#### a. Get the source code:
```bash
argot_show_src <function_regex>
```

#### b. Get the SSA representation:
```bash
argot_show_ssa <function_regex>
```

#### c. Analyze data flows:
- Trace how each argument flows through the function
- Identify which arguments affect which return values
- Look for mutations to pointer/slice arguments
- Consider all execution paths (branches, loops, error cases)

### 5. Generate Summary

Create a YAML entry following this format:

```yaml
dataflow-summaries:
  # func FunctionName(arg1 type1, arg2 type2) (ret1 type1, ret2 type2)
  - package: "package/name"
    function: "FunctionName"  # for standalone functions
    # OR for methods:
    # receiver: "*StructName"
    # method: "MethodName"
    flows:
      - from: "!arg 0"  # first argument
        to: "!ret 0"    # first return value
      - from: "!arg 1"
        to: "!ret 1"
      # For mutations to pointer arguments:
      - from: "!arg 1"
        to: "(!arg 1)[*]"
```

### 6. Flow Identifiers

- `!arg 0`, `!arg 1`, etc. - Function arguments by position
- `!arg <name>` - Function arguments by name  
- `!receiver` - Method receiver (methods only)
- `!ret`, `!ret 0`, `!ret 1`, etc. - Return values by position
- `(!arg N)[*]` - Flow through pointer/slice/map elements
- `(!arg N).field` - Flow through struct field

### 7. Analysis Guidelines

**Be Conservative**: Include all possible data flows to ensure soundness. It's better to over-approximate than miss a flow.

**Consider All Paths**: Account for all execution paths including:
- Error conditions
- Different branches in switch/if statements
- Loop iterations
- Deferred functions

**Handle Mutations**: If a function modifies its arguments (pointers, slices, maps), include flows back to them using `(!arg N)[*]` notation.

### 8. Verification

#### a. Add function signatures as comments:
```yaml
# func FunctionName(arg1 type1, arg2 type2) (ret1 type1, ret2 type2)
- package: "package/name"
  function: "FunctionName"
  flows: [...]
```

#### b. Verify consistency:
- Argument count matches between signature and flows
- Return value count matches
- Flow directions make logical sense

#### c. Test the analysis (with timeout initially):
```bash
timeout 60s argot taint -config argot-config.yaml 2>&1 | grep "should have a summary"
```

The number of warnings should decrease as you add summaries. Once you have most summaries, you can remove the timeout.

## Example

For a function like:
```go
func Getrlimit(which int, lim *Rlimit) (err error)
```

The summary would be:
```yaml
# func Getrlimit(which int, lim *Rlimit) (err error)
- package: "syscall"
  function: "Getrlimit"
  flows:
    - from: "!arg 0"      # which affects error
      to: "!ret 0"
    - from: "!arg 1"      # syscall modifies *lim
      to: "(!arg 1)[*]"
```

## Common Patterns

### System Calls
Most system calls flow all arguments to error returns and may modify pointer arguments:
```yaml
flows:
  - from: "!arg 0"
    to: "!ret 0"  # error
  - from: "!arg 1" 
    to: "(!arg 1)[*]"  # if pointer argument is modified
```

### Network Functions
Network functions typically flow network/address parameters to both connection and error returns:
```yaml
flows:
  - from: "!arg 0"  # network
    to: "!ret 1"    # error
  - from: "!arg 1"  # address
    to: "!ret 0"    # connection
  - from: "!arg 1"
    to: "!ret 1"    # error
```

### No-op Functions
Functions with no inputs/outputs or no data flows:
```yaml
flows: []
```

## File Structure

Save summaries in `user-specs.yaml` with the format:
```yaml
dataflow-summaries:
  - package: "..."
    function: "..."
    flows: [...]
  - package: "..."
    receiver: "..."
    method: "..."
    flows: [...]
```

## Quality Assurance

1. **Completeness**: All warned functions should have summaries
2. **Correctness**: Flows should match actual function behavior
3. **Consistency**: Signatures should match the actual function signatures
4. **Soundness**: Over-approximate rather than under-approximate flows

## Timeout Strategy

- **Initial runs**: Use `timeout 60s` to avoid long waits
- **After basic summaries**: Can increase timeout or remove it
- **Final verification**: Run without timeout to ensure completeness
