# Argot MCP Server

The Argot MCP (Model Context Protocol) server exposes Argot's static analysis capabilities to AI assistants and other clients through a standardized protocol. This enables interactive Go code analysis and automated generation of dataflow summaries for taint analysis.

## Setup

Build and run the MCP server:

```bash
cd cmd/argot-mcp-server
go build -o argot-mcp-server main.go
./argot-mcp-server
```

The server communicates via stdin/stdout using JSON-RPC 2.0 protocol.

## Available Tools

The MCP server provides access to Argot's analysis tools through a stateful interface. Most operations require loading a program first, then performing various analyses on the loaded code.

### Program Management

- **argot_load** - Loads Go programs for analysis by parsing source files and building SSA representation
- **argot_program_rebuild** - Rebuilds the currently loaded program and reinitializes complex analyses
- **argot_show_state** - Displays the current analysis state including loaded programs and available analyses

### Code Discovery and Inspection

- **argot_list_functions** - Lists functions matching a regex pattern, with options to filter by reachability or summarization status
- **argot_members** - Prints package members including functions, types, constants, and global variables
- **argot_show_src** - Displays the original Go source code for functions matching a pattern
- **argot_print_ast** - Shows the Abstract Syntax Tree representation of functions or entire files
- **argot_show_ssa** - Displays the SSA (Static Single Assignment) form which is essential for understanding data flow
- **argot_show_stats** - Provides comprehensive program statistics including SSA usage, defers, and closures

### Function-Level Analysis

- **argot_function_focus** - Focuses analysis on a specific function to enable detailed value inspection
- **argot_function_unfocus** - Removes focus from the current function to allow global operations
- **argot_show_ssa_value** - Examines specific SSA values showing type information and usage (requires focused function)
- **argot_show_ssa_instr** - Displays detailed information about specific SSA instructions (requires focused function)
- **argot_focused_mayalias** - Checks whether values may alias each other (requires focused function)

### Advanced Analysis

- **argot_run_pointer** - Executes pointer analysis to determine aliasing relationships, essential for precise dataflow analysis
- **argot_show_callees** - Shows functions that may be called by a given function, using pointer analysis when available
- **argot_show_callers** - Shows functions that may call a given function, using pointer analysis when available
- **argot_dataflow_summarize** - Builds dataflow summaries for functions using intra-procedural analysis (computationally expensive)
- **argot_dataflow_summary** - Prints the internal dataflow summaries

### Utility Tools

- **argot_scan** - Scans the AST for identifiers and types matching regex patterns
- **go_dependencies** - Analyzes Go package dependencies and identifies underutilized dependencies

## Available Prompts

The server provides specialized prompts to guide AI assistants in performing complex analysis tasks.

### dataflow-summary-generation

This comprehensive prompt guides the generation of dataflow summaries for Go functions. The prompt includes complete specifications for the YAML format used by Argot's taint analysis, flow identifier syntax, and a step-by-step workflow using the available analysis tools. It requires three inputs: the file path containing the function, the function name, and the package name.

## Usage Patterns

The typical workflow involves loading a program, discovering functions of interest, inspecting their source and SSA representations, optionally running pointer analysis for precision, and then performing specific analyses. For dataflow summary generation, the process follows the embedded prompt workflow which systematically analyzes function behavior to produce accurate summaries.

The stateful nature of the server means that analyses build upon each other - loading a program enables function discovery, focusing on a function enables value inspection, and running pointer analysis improves the precision of call graph operations.

## Integration

To integrate with AI assistants supporting MCP, configure the server in your client's MCP settings. The server exposes both tools for interactive analysis and prompts for guided tasks like dataflow summary generation.

```json
{
  "mcpServers": {
    "argot": {
      "command": "./argot-mcp-server",
      "args": []
    }
  }
}
```